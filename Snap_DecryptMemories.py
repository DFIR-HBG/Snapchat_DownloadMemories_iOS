import os
import base64
from Crypto.Cipher import AES
import sys
from binascii import unhexlify
from binascii import hexlify
from shutil import copy2, rmtree
import pandas as pd
import requests
import sqlite3
import ccl_bplist
import filetype
import subprocess

header_size = 0x10
page_size=0x400
salt_sz = 0x10
hmac_sz = 0x20
reserved_sz = salt_sz + hmac_sz

def decryptGallery(db, key):
	global header, max_page
	
	enc_db = open(db, "rb")
	enc_db_size = os.path.getsize(db)
	try:
		key = unhexlify(key)
		#print(f"key is: {key}")
	except:
		key = base64.b64decode(key)
		#print(f"key is: {key}")
		
	header = enc_db.read(header_size)
	max_page = int(enc_db_size / page_size)
	with open(decryptedName,'wb') as decrypted:
		decrypted.write(b'SQLite format 3\x00')
		
		for page in range(0,max_page):
			decrypted.write(decrypt_page(page, enc_db, key))
			decrypted.write(b'\x00'*reserved_sz)
	print(f"Database decrypted: {decryptedName}")

def decrypt_page(page_offset, enc_db, key):
	if page_offset == 0:
		page_data = enc_db.read(page_size - header_size)
	else:
		page_data = enc_db.read(page_size)
	
	iv = page_data[-reserved_sz:-reserved_sz+salt_sz]
	decryption_suite = AES.new(key[:32], AES.MODE_CBC, iv)
	plain_text = decryption_suite.decrypt(page_data[:-reserved_sz])
	
	return plain_text

def getMemoryKey(db):
	conn = sqlite3.connect(db)
	query= """
	select
	snap_id as ID,
	KEY as KEY,
	IV as IV,
	ENCRYPTED as ENCRYPTED
	from snap_key_iv"""

	df = pd.read_sql_query(query, conn)

	return df

def getSCDBInfo(db):
	conn = sqlite3.connect(db)
	query= """
	select
	ZMEDIAID as ID,
	ZMEDIADOWNLOADURL,
	ZOVERLAYDOWNLOADURL
	from ZGALLERYSNAP
	WHERE ZMEDIADOWNLOADURL IS NOT NULL"""

	df = pd.read_sql_query(query, conn)

	return df

def getMemoriesFromURL(df):

	os.makedirs("DecryptedMemories", exist_ok=True)
	for index, row in df.iterrows():
		r = requests.get(row["ZMEDIADOWNLOADURL"], allow_redirects=True)
		with open(f"./DecryptedMemories/{row['ID']}", 'wb') as f:
			f.write(r.content)
		print("got file")

		if row["ZOVERLAYDOWNLOADURL"] != None:
			print(row["ZOVERLAYDOWNLOADURL"])
			rOverlay = requests.get(row["ZOVERLAYDOWNLOADURL"], allow_redirects=True)
			if rOverlay.status_code == 200:
				with open(f"./DecryptedMemories/{row['ID']}_overlay", 'wb') as f:
					f.write(rOverlay.content)
				print("got overlay")
				break;

def fixMEOkeys(persistedKey, df_merge):

	with open("temp.plist", "wb") as f:
		f.write(persistedKey)
	with open("temp.plist", "rb") as f:
		MEOplist = ccl_bplist.load(f)
	os.remove("temp.plist")

	obj = ccl_bplist.deserialise_NsKeyedArchiver(MEOplist)
	MEOkey = obj["masterKey"]
	MEOiv = obj["initializationVector"]
	
	for index, row in df_merge.iterrows():
		if row["ENCRYPTED"] == 1:
			enc_key = row["KEY"]
			enc_iv = row["IV"]
			aes = AES.new(MEOkey, AES.MODE_CBC, MEOiv)
			dec_key = hexlify(aes.decrypt(enc_key))[:64]
			aes = AES.new(MEOkey, AES.MODE_CBC, MEOiv)
			dec_iv = hexlify(aes.decrypt(enc_iv))[:32]
			df_merge.loc[index, "KEY"] = unhexlify(dec_key)
			df_merge.loc[index, "IV"] = unhexlify(dec_iv)

	return df_merge

def decryptMemories(egocipherKey, persistedKey, df_merge):
	
	try:
		egocipherKey = unhexlify(egocipherKey)
		persistedKey = unhexlify(persistedKey)
	except:
		egocipherKey = base64.b64decode(egocipherKey)
		persistedKey = base64.b64decode(persistedKey)

	df_merge = fixMEOkeys(persistedKey, df_merge)

	for index, row in df_merge.iterrows():
		try:
			aes = AES.new(row["KEY"], AES.MODE_CBC, row["IV"])
			file = f"DecryptedMemories/{row['ID']}"
			print(f"Decrypting {file}")
			with open(file, "rb") as f:
				enc_data = f.read()
			dec_data = aes.decrypt(enc_data)

			kind = filetype.guess(dec_data)
			if kind != None:
				with open(file+"."+kind.extension, "wb") as f:
					f.write(dec_data)
			else:
				print(f"Could not find file extension of {file}")
				with open(file+"."+"nokind", "wb") as f:
					f.write(dec_data)

			overlayFile = file + "_overlay"
			if os.path.exists(overlayFile):
				print(f"Decrypting overlay: {overlayFile}")
				with open(overlayFile, "rb") as f:
					enc_data = f.read()
				dec_data = aes.decrypt(enc_data)

				kind = filetype.guess(dec_data)
				if kind != None:
					with open(overlayFile+"."+kind.extension, "wb") as f:
						f.write(dec_data)
				else:
					print(f"Could not find file extension of {overlayFile}")
					with open(overlayFile+"."+"nokind", "wb") as f:
						f.write(dec_data)

		except Exception as Error:
			print(f"Error decryption snap ID {row['ID']} {Error}")


def recoverDatabase():
	subprocess.call(["sqlite3", decryptedName, ".output recovery.sql", ".dump"])
	recoveredFile = decryptedName + "_r"
	if os.path.exists(recoveredFile):
		os.remove(recoveredFile)
	recoveredConn = None
	try:
		recoveredConn = sqlite3.connect(recoveredFile)
	except Error as e:
		print(e)
	with open("recovery.sql", "r") as recoverySql:
		recoveredConn.executescript(recoverySql.read())
		recoveredConn.close
	print("Database Recovered!")


def main():
	global decryptedName
	
	enc_db = sys.argv[1]
	scdb = sys.argv[2]
	egocipherKey = sys.argv[3]
	try:
		persistedKey = sys.argv[4]
	except:
		persistedKey = ""
	decryptedName = "gallery_decrypted.sqlite"
	decryptGallery(enc_db, egocipherKey)
	recoverDatabase()
	#print("OPEN UP THE GALLERY_DECRYPTED.DB IN FORENSIC SQLITE BROWSER")
	#os.system("pause")
	

	df_MemoryKey = getMemoryKey(decryptedName + "_r")
	df_SCDBInfo = getSCDBInfo(scdb)

	df_merge = pd.merge(df_MemoryKey, df_SCDBInfo, on=["ID"])

	
	getMemoriesFromURL(df_merge)

	decryptMemories(egocipherKey, persistedKey, df_merge)

	print("Decrypted memories can be found in the DecryptedMemories folder")
	

if __name__ == "__main__":
	main()
