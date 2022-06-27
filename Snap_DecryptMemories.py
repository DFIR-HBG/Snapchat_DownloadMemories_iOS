import os
import base64
from sqlite3.dbapi2 import DatabaseError
from Crypto.Cipher import AES
import sys
from binascii import unhexlify
from binascii import hexlify
from shutil import copy2, rmtree
from datetime import datetime
import calendar
import pandas as pd
import requests
import sqlite3
import ccl_bplist
import filetype
import subprocess
from PIL import Image

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

def getFullSCDBInfo(db):
	conn = sqlite3.connect(db)
	query= """
	select
	ZMEDIAID as ID,
	*
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
			rOverlay = requests.get(row["ZOVERLAYDOWNLOADURL"], allow_redirects=True)
			if rOverlay.status_code == 200:
				with open(f"./DecryptedMemories/{row['ID']}_overlay", 'wb') as f:
					f.write(rOverlay.content)
				print("got overlay")




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
	df_merge["filename"] = ""
	df_merge["overlayFilename"] = ""
	for index, row in df_merge.iterrows():
		try:
			aes = AES.new(row["KEY"], AES.MODE_CBC, row["IV"])
			filename = row['ID']
			file = f"DecryptedMemories/{filename}"
			print(f"decrypting {file}")
			with open(file, "rb") as f:
				enc_data = f.read()
			dec_data = aes.decrypt(enc_data)

			kind = filetype.guess(dec_data)
			if kind != None:
				with open(file+"."+kind.extension, "wb") as f:
					f.write(dec_data)
					df_merge.loc[index, "filename"] = filename+"."+kind.extension
			else:
				print(f"could not find file extension of {file}")
				with open(file+"."+"nokind", "wb") as f:
					f.write(dec_data)
					df_merge.loc[index, "filename"] = filename+"."+"nokind"
				
			overlayFilename = filename + "_overlay"
			overlayFile = f"DecryptedMemories/{overlayFilename}"
			if os.path.exists(overlayFile):
				aes = AES.new(row["KEY"], AES.MODE_CBC, row["IV"])
				print(f"Decrypting overlay: {overlayFile}")
				with open(overlayFile, "rb") as f:
					enc_data = f.read()
				dec_data = aes.decrypt(enc_data)

				kind = filetype.guess(dec_data)
				if kind != None:
					with open(overlayFile+"."+kind.extension, "wb") as f:
						f.write(dec_data)
						df_merge.loc[index, "overlayFilename"] = overlayFilename+"."+kind.extension
				else:
					print(f"Could not find file extension of {overlayFile}")
					with open(overlayFile+"."+"nokind", "wb") as f:
						f.write(dec_data)
						df_merge.loc[index, "overlayFilename"] = overlayFilename+"."+"nokind"
		except Exception as Error:
			
			print(f"Error decryption snap ID {row['ID']} {Error}")

	return df_merge

def timestampsconv(cocoaCore):
	if pd.isna(cocoaCore):
		return ""
	unix_timestamp = cocoaCore + 978307200
	finaltime = datetime.utcfromtimestamp(unix_timestamp)
	return(finaltime)

def recoverWithSqlite():
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
	os.remove("recovery.sql")
	print("Database Recovered!")

def recoverWithTool():
	print("OPEN UP THE GALLERY_DECRYPTED.DB IN FORENSIC SQLITE BROWSER - Make sure recovered database is named  GALLERY_DECRYPTED.DB_r")
	os.system("pause")

def isSqliteInstalled() -> bool:
	try:
		subprocess.call(["sqlite3", "-version"])
	except FileNotFoundError as e:
		print("SQLite3 not installed")
		return False
	return True


def checkDatabase() -> bool:
	try:
		conn = sqlite3.connect(decryptedName)
		query= """
		SELECT name FROM sqlite_schema
		WHERE type='table'
		ORDER BY name"""

		df = conn.execute(query)
	except sqlite3.DatabaseError as e:
		return False
	return True
	

def recoverDatabase():
	databaseValid = checkDatabase()
	if databaseValid:
		return
	else:
		if isSqliteInstalled():
			recoverWithSqlite()
		else:
			recoverWithTool()



def createFullSnapImages(df_merge):
	pattern = '_overlay'
	filePath = "DecryptedMemories/"
	os.makedirs("DecryptedMemories/FullSnap", exist_ok=True)
	for index, row in df_merge.iterrows():
		filename = row['filename']
		if filename != "":
			file = filePath + filename
			#need to detect videos
			fileTypeMime = filetype.guess(file).mime
			if fileTypeMime != "video/mp4" and fileTypeMime != "video/quicktime":
				background = Image.open(file)
				if row['overlayFilename'] != "":
					foreground = Image.open(filePath + row['overlayFilename'])
					background.paste(foreground, (0, 0), foreground)
				background.save(filePath + 'FullSnap/' + filename)
			else:
				print("VIDEO FILES NOT SUPPORTED YET")

def generateReport(df_merge):
	filePath = "./DecryptedMemories/"
	createFullSnapImages(df_merge)
	df_report = pd.DataFrame(columns=['ID', 'Image', 'Overlay'])
	for index, row in df_merge.iterrows():
		id = row['ZMEDIAID']
		format = row['ZSERVLETMEDIAFORMAT']
		columns = ['ID', 'Image', 'Overlay', 'Create Time (UTC)', 'Capture Time (UTC)', 'Duration', 'Camera']
		createTime = timestampsconv(row['ZCREATETIMEUTC'])
		captureTime = timestampsconv(row['ZCAPTURETIMEUTC'])
		duration = row['ZDURATION']
		camera = "Front" if row['ZCAMERAFRONTFACING'] == 1 else "Back"
		if row['overlayFilename'] != "":
			if format[0:5] == "video":
				rowData = [id, 
						   makeVideo(filePath + row['filename']), 
						   makeImg(filePath + row['overlayFilename']),
						   createTime,
						   captureTime,
						   duration,
						   camera
						   ]
				
			else:
				rowData = [id, 
							makeImg(filePath + "FullSnap/" + row['filename']), 
							makeImg(filePath + row['overlayFilename']),
						   createTime,
						   captureTime,
						   duration,
						   camera
							]
		else:
			if format[0:5] == "video":
				rowData = [id, 
							makeVideo(filePath + row['filename']), 
							"",
						   createTime,
						   captureTime,
						   duration,
						   camera
							]
			else:
				rowData = [id, 
							makeImg(filePath + "FullSnap/" + 
							row['filename']), 
							"",
						   createTime,
						   captureTime,
						   duration,
						   camera
							]
		df_row = pd.DataFrame([rowData], columns=columns)
		df_report = pd.concat([df_report, df_row])
		df_report.sort_values(by=["Create Time (UTC)"], ascending=True, inplace=True)
		print(f'Records Added to Report: {len(df_report)}')

	df_report.to_html(open('report.html', 'w'), escape=False, index=False)
	

def makeImg(src):
	return f'<img src="{src}" width="200"/>'


def makeVideo(src):
	return f'<video width="200" preload="none" controls><source src="{src}" type="video/mp4">Your browser does not support the video tag.</video><a href="{src}" download>Download</a>'

def promptDate(type):
	date_entry = input(f'Enter {type} date in YYYY-MM-DD format. Leave blank to skip\n')
	
	if date_entry == "":
		return None

	year, month, day = map(int, date_entry.split('-'))
	if(type == "end"):
		day = day+1
	dt = datetime(year, month, day)
	
	return getCocoaCoreTime(dt)

def getCocoaCoreTime(dt):
	unix_timestamp = calendar.timegm(dt.timetuple())
	cocoaCore = unix_timestamp - 978307200
	return(cocoaCore)

def filterDfByDates(df_merge, start_date, end_date):
	if start_date != None and end_date != None:
		return df_merge[(df_merge['ZCREATETIMEUTC'] >= start_date) & (df_merge['ZCREATETIMEUTC'] < end_date)]
	elif start_date != None:
		return df_merge[(df_merge['ZCREATETIMEUTC'] >= start_date)]
	elif end_date != None:
		return df_merge[(df_merge['ZCREATETIMEUTC'] < end_date)]
	else:
		return df_merge



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

	start_date = promptDate("start")
	end_date = promptDate("end")

	

	
	decryptGallery(enc_db, egocipherKey)
	
	recoverDatabase()

	df_MemoryKey = getMemoryKey(decryptedName + "_r")
	df_SCDBInfo = getFullSCDBInfo(scdb)
	df_merge = pd.merge(df_MemoryKey, df_SCDBInfo, on=["ID"])
	
	df_merge = filterDfByDates(df_merge, start_date, end_date)
	
	getMemoriesFromURL(df_merge)

	df_merge = decryptMemories(egocipherKey, persistedKey, df_merge)
	
	generateReport(df_merge)
	print("Decrypted memories can be found in the DecryptedMemories folder. report.html can be found in Current Folder")
	

if __name__ == "__main__":
	main()
