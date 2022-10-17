import os
import base64
import plistlib
from sqlite3.dbapi2 import DatabaseError
from Crypto.Cipher import AES
import sys
from binascii import unhexlify
from binascii import hexlify
from datetime import datetime
import calendar
import pandas as pd
import requests
import sqlite3
from scripts import ccl_bplist
from scripts import keychain as convert_keychain
import filetype
import subprocess
from PIL import Image
import shutil

header_size = 0x10
page_size = 0x400
salt_sz = 0x10
hmac_sz = 0x20
reserved_sz = salt_sz + hmac_sz


def decryptGallery(db, egocipher):
    global header, max_page
    
    key = egocipher

    enc_db = open(db, "rb")
    enc_db_size = os.path.getsize(db)

    header = enc_db.read(header_size)
    max_page = int(enc_db_size / page_size)
    with open(decryptedName, 'wb') as decrypted:
        decrypted.write(b'SQLite format 3\x00')

        for page in range(0, max_page):
            decrypted.write(decrypt_page(page, enc_db, key))
            decrypted.write(b'\x00' * reserved_sz)
    print(f"Database decrypted: {decryptedName}")


def decrypt_page(page_offset, enc_db, key):
    if page_offset == 0:
        page_data = enc_db.read(page_size - header_size)
    else:
        page_data = enc_db.read(page_size)

    iv = page_data[-reserved_sz:-reserved_sz + salt_sz]
    decryption_suite = AES.new(key[:32], AES.MODE_CBC, iv)
    plain_text = decryption_suite.decrypt(page_data[:-reserved_sz])

    return plain_text


def getMemoryKey(db):
    conn = sqlite3.connect(db)
    query = """
	select
	snap_key_iv.snap_id as ID,
	snap_key_iv.KEY as KEY,
	snap_key_iv.IV as IV,
	snap_key_iv.ENCRYPTED as ENCRYPTED,
	snap_location_table.snap_id,
	snap_location_table.latitude as latitude,
	snap_location_table.longitude as longitude
	from snap_key_iv
	left join snap_location_table on ID = snap_location_table.snap_id"""

    df = pd.read_sql_query(query, conn)

    return df


def getSCDBInfo(db):
    conn = sqlite3.connect(db)
    query = """
	select
	ZSNAPID as ID,
	ZMEDIADOWNLOADURL,
    ZMEDIAREDIRECTURI,
	ZOVERLAYDOWNLOADURL,
    ZOVERLAYREDIRECTURI
	from ZGALLERYSNAP
	"""
    # WHERE ZMEDIADOWNLOADURL IS NOT NULL
    df = pd.read_sql_query(query, conn)

    return df


def getFullSCDBInfo(db):
    conn = sqlite3.connect(db)
    query = """
	select
	ZSNAPID as ID,
	*
	from ZGALLERYSNAP
	"""
    # WHERE ZMEDIADOWNLOADURL IS NOT NULL
    df = pd.read_sql_query(query, conn)

    return df


def getMemoriesFromURL(df):
    os.makedirs("EncryptedMemories", exist_ok=True)
    count = 0
    total = len(df)
    for index, row in df.iterrows():
        count += 1
        if os.path.exists(f"EncryptedMemories/{row['ID']}") or os.path.exists(f"EncryptedMemories/{row['ID']}_overlay"):
            print(f"File or overlay for {row['ID']} already exists in EncryptedMemories, assuming it is already downloaded - Skipping to next")
            continue
            
        if row["ENCRYPTED"] == 0:
            if row["ZMEDIADOWNLOADURL"] is not None:
                print(f"Downloading Memory          {row['ID']} ({count}/{total})")
                
            elif row["ZMEDIAREDIRECTURI"] is not None and row["ZMEDIAREDIRECTURI"].startswith("https"):
                df.loc[index, "ZMEDIADOWNLOADURL"] = row["ZMEDIAREDIRECTURI"]
                print(f"Downloading Memory          {row['ID']} ({count}/{total})")
                
            else:
                print(f"No Download link for Memory {row['ID']} ({count}/{total})")
                df = df.drop(index)
                continue
        else:
            if row["ZMEDIADOWNLOADURL"] is not None:
                print(f"Downloading MEO             {row['ID']} ({count}/{total})")
                
            elif row["ZMEDIAREDIRECTURI"] is not None and row["ZMEDIAREDIRECTURI"].startswith("https"):
                df.loc[index, "ZMEDIADOWNLOADURL"] = row["ZMEDIAREDIRECTURI"]
                print(f"Downloading MEO             {row['ID']} ({count}/{total})")
                
            else:
                print(f"No Download link for MEO {row['ID']} ({count}/{total})")
                df = df.drop(index)
                continue

        r = requests.get(row["ZMEDIADOWNLOADURL"], allow_redirects=True)
        if r.status_code == 200:
            with open(f"EncryptedMemories/{row['ID']}", 'wb') as f:
                f.write(r.content)
            print("------------------------ Done ------------------------")
        else:
            print(f"Could not download file, Status code: {r.status_code}")

        if row["ZOVERLAYDOWNLOADURL"] is not None:
            print(f"Downloading Overlay for     {row['ID']} ({count}/{total})")
        elif row["ZOVERLAYREDIRECTURI"] is not None and row["ZOVERLAYREDIRECTURI"].startswith("https"):
            df.loc[index, "ZOVERLAYDOWNLOADURL"] = row["ZOVERLAYREDIRECTURI"]
        else:
            continue
            
        rOverlay = requests.get(row["ZOVERLAYDOWNLOADURL"], allow_redirects=True)
        if rOverlay.status_code == 200:
            with open(f"EncryptedMemories/{row['ID']}_overlay", 'wb') as f:
                f.write(rOverlay.content)
            print("------------------------ Done ------------------------")
        else:
            print(f"Could not download overlay, Status code: {r.status_code}")
            


def fixMEOkeys(persistedKey, df_merge):
    print("Fixing MEO keys")
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
    if not isinstance(egocipherKey, bytes):
        try:
            egocipherKey = unhexlify(egocipherKey)
            persistedKey = unhexlify(persistedKey)
        except:
            try:
                egocipherKey = base64.b64decode(egocipherKey)
                persistedKey = base64.b64decode(persistedKey)
            except Exception as E:
                print("Could not decode keys", E)
                print(f"Egocipher: {egocipherKey}")
                print(f"")

    # print("PERSISTEDKEY = ", persistedKey)
    if persistedKey != "" and persistedKey != b'':
        df_merge = fixMEOkeys(persistedKey, df_merge)

    df_merge["filename"] = ""
    df_merge["overlayFilename"] = ""
    for index, row in df_merge.iterrows():
        try:
            aes = AES.new(row["KEY"], AES.MODE_CBC, row["IV"])
            filename = row['ID']
            file = f"EncryptedMemories/{filename}"
            print(f"Decrypting {file}")
            with open(file, "rb") as f:
                enc_data = f.read()
            dec_data = aes.decrypt(enc_data)

            fileTypeMime = filetype.guess(dec_data)
            if fileTypeMime is not None:
                with open(outputDir + "/DecryptedMemories/" + filename + "." + fileTypeMime.extension, "wb") as f:
                    f.write(dec_data)
                    df_merge.loc[index, "filename"] = filename + "." + fileTypeMime.extension
            else:
                print(f"could not find file extension of {file}")
                with open(outputDir + "/DecryptedMemories/" + filename + "." + "nokind", "wb") as f:
                    f.write(dec_data)
                    df_merge.loc[index, "filename"] = filename + "." + "nokind"

            overlayFilename = filename + "_overlay"
            overlayFile = f"EncryptedMemories/{overlayFilename}"
            if os.path.exists(overlayFile):
                aes = AES.new(row["KEY"], AES.MODE_CBC, row["IV"])
                print(f"Decrypting overlay: {overlayFile}")
                with open(overlayFile, "rb") as f:
                    enc_data = f.read()
                dec_data = aes.decrypt(enc_data)

                fileTypeMime = filetype.guess(dec_data)
                if fileTypeMime is not None:
                    with open(outputDir + "/DecryptedMemories/" + overlayFilename + "." + fileTypeMime.extension,
                              "wb") as f:
                        f.write(dec_data)
                        df_merge.loc[index, "overlayFilename"] = overlayFilename + "." + fileTypeMime.extension
                else:
                    print(f"Could not find file extension of {overlayFile}")
                    with open(outputDir + "/DecryptedMemories/" + overlayFile + "." + "nokind", "wb") as f:
                        f.write(dec_data)
                        df_merge.loc[index, "overlayFilename"] = overlayFilename + "." + "nokind"
        except FileNotFoundError as fnfe:
            continue
        except Exception as error:
            print(f"Error decryption snap ID {row['ID']} {error}")

    return df_merge


def timestampsconv(cocoaCore):
    if pd.isna(cocoaCore):
        return ""
    unix_timestamp = cocoaCore + 978307200
    finaltime = datetime.utcfromtimestamp(unix_timestamp)
    return (finaltime)


def recoverWithSqlite():
    subprocess.call(["sqlite3", decryptedName, ".output recovery.sql", ".dump"])
    recoveredFile = decryptedName + "_r"
    if os.path.exists(recoveredFile):
        os.remove(recoveredFile)
    recoveredConn = None
    try:
        recoveredConn = sqlite3.connect(recoveredFile)
    except DatabaseError as e:
        print(e)
    with open("recovery.sql", "r") as recoverySql:
        recoveredConn.executescript(recoverySql.read())
        recoveredConn.close()
    os.remove("recovery.sql")
    print("Database Recovered!")


def recoverWithTool():
    print(
        "OPEN UP THE GALLERY_DECRYPTED.DB IN FORENSIC SQLITE BROWSER - Make sure recovered database is named  GALLERY_DECRYPTED.DB_r")
    os.system("pause")


def isSqliteInstalled() -> bool:
    try:
        subprocess.call(["sqlite3", "-version"], stdout=subprocess.DEVNULL)
    except FileNotFoundError as e:
        print("SQLite3 not installed")
        return False
    return True


def checkDatabase() -> bool:
    try:
        conn = sqlite3.connect(decryptedName)
        query = """
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
    filePath = f"{outputDir}/DecryptedMemories/"
    os.makedirs(f"{outputDir}/DecryptedMemories/FullSnap", exist_ok=True)
    for index, row in df_merge.iterrows():
        filename = row['filename']
        if filename != "":
            file = filePath + filename
            # need to detect videos
            fileTypeMime = filetype.guess(file).mime
            if fileTypeMime != "video/mp4" and fileTypeMime != "video/quicktime":
                background = Image.open(file)
                if row['overlayFilename'] != "":
                    try:
                        foreground = Image.open(filePath + row['overlayFilename'])
                        background.paste(foreground, (0, 0), foreground)
                    except:
                        pass
                background.save(filePath + 'FullSnap/' + filename)
            else:
                continue
                #print("VIDEO FILES NOT SUPPORTED YET")


def generateReport(df_merge):
    if getattr(sys, 'frozen', False):
        exe_path = sys._MEIPASS
        try:
            shutil.copytree(f"{exe_path}/css", f"{outputDir}/css")
        except:
            print("Could not copy the CSS folder, result might look a bit worse")
    else:
        exe_path = os.path.dirname(os.path.abspath(__file__))
        try:
            shutil.copytree(f"{exe_path}/scripts/data/css", f"{outputDir}/css")
        except:
            print("Could not copy the CSS folder, result might look a bit worse")

    filePath = f"./DecryptedMemories/"
    createFullSnapImages(df_merge)
    df_report = pd.DataFrame(columns=['ID', 'Image', 'Overlay'])
    for index, row in df_merge.iterrows():
        if row["ENCRYPTED"] == 1:
            memoryType = "My Eyes Only"
        else:
            memoryType = "Memory"
        id = row['ZMEDIAID']
        format = row['ZSERVLETMEDIAFORMAT']
        columns = ['ID', 'Memory Type', 'Image', 'Overlay', 'Create Time (UTC)', 'Capture Time (UTC)', 'Duration', 'Camera', 'longitude', 'latitude']
        createTime = timestampsconv(row['ZCREATETIMEUTC'])
        captureTime = timestampsconv(row['ZCAPTURETIMEUTC'])
        duration = row['ZDURATION']
        camera = "Front" if row['ZCAMERAFRONTFACING'] == 1 else "Back"
        if row['overlayFilename'] != "":
            if format[0:5] == "video":
                rowData = [id,
                           memoryType,
                           makeVideo(filePath + row['filename']),
                           makeImg(filePath + row['overlayFilename']),
                           createTime,
                           captureTime,
                           duration,
                           camera,
                           row['longitude'],
                           row['latitude']
                           ]

            else:
                rowData = [id,
                           memoryType,
                           makeImg(filePath + "FullSnap/" + row['filename']),
                           makeImg(filePath + row['overlayFilename']),
                           createTime,
                           captureTime,
                           duration,
                           camera,
                           row['longitude'],
                           row['latitude']
                           ]
        else:
            if format[0:5] == "video":
                rowData = [id,
                           memoryType,
                           makeVideo(filePath + row['filename']),
                           "",
                           createTime,
                           captureTime,
                           duration,
                           camera,
                           row['longitude'],
                           row['latitude']
                           ]
            else:
                rowData = [id,
                           memoryType,
                           makeImg(filePath + "FullSnap/" +
                                   row['filename']),
                           "",
                           createTime,
                           captureTime,
                           duration,
                           camera,
                           row['longitude'],
                           row['latitude']
                           ]
        df_row = pd.DataFrame([rowData], columns=columns)
        df_report = pd.concat([df_report, df_row])
        df_report.sort_values(by=["Create Time (UTC)"], ascending=True, inplace=True)
    print(f'Records Added to Report: {len(df_report)}')

    template = """
    <body>%s
    </body>
    """

    html = """
    <link href="./css/bootstrap.min.css" rel="stylesheet">
    <style>
    th {
        background: #2d2d71;
        color: white;
        text-align: left;
    }
    </style>
        """
    html = html + template % df_report.to_html(classes=["table table-bordered table-striped table-hover table-xl "
                                                        "table-responsive text-wrap"], escape=False, index=False)
    html = html.replace('<img src="./DecryptedMemories/FullSnap/" width="200"/>', "Could not be downloaded or "
                                                                                  "decrypted, usually because no "
                                                                                  "download link was available")
    html = html.replace('<video width="200" preload="none" controls><source src="./DecryptedMemories/" '
                        'type="video/mp4">Your browser does not support the video tag.</video><a '
                        'href="./DecryptedMemories/" download>Download</a>', "Could not be downloaded or decrypted, "
                                                                             "usually because no download link was "
                                                                             "available")
    with open(f'{outputDir}/Report.html', 'w') as f:
        f.write(html)


def makeImg(src):
    return f'<img src="{src}" width="200"/>'


def makeVideo(src):
    return f'<video width="200" preload="none" controls><source src="{src}" type="video/mp4">Your browser does not ' \
           f'support the video tag.</video><a href="{src}" download>Download</a> '


def promptDate(type):
    date_entry = input(f'Enter {type} date in YYYY-MM-DD format. Leave blank to skip\n')

    if date_entry == "":
        return None

    year, month, day = map(int, date_entry.split('-'))
    if type == "end":
        day = day + 1
    dt = datetime(year, month, day)

    return getCocoaCoreTime(dt)


def getCocoaCoreTime(dt):
    unix_timestamp = calendar.timegm(dt.timetuple())
    cocoaCore = unix_timestamp - 978307200
    return (cocoaCore)


def filterDfByDates(df_merge, start_date, end_date):
    if start_date is not None and end_date is not None:
        return df_merge[(df_merge['ZCREATETIMEUTC'] >= start_date) & (df_merge['ZCREATETIMEUTC'] < end_date)]
    elif start_date is not None:
        return df_merge[(df_merge['ZCREATETIMEUTC'] >= start_date)]
    elif end_date is not None:
        return df_merge[(df_merge['ZCREATETIMEUTC'] < end_date)]
    else:
        return df_merge


def readKeychain(keychain):
    egocipher = ""
    persisted = ""
    with open(keychain, "rb") as f:
        keychain_plist = plistlib.load(f)
    try:  # GK Keychain
        for x in keychain_plist.values():
            for y in x:
                if 'agrp' in y.keys():
                    if b'3MY7A92V5W.com.toyopagroup.picaboo' == y['agrp']:
                        # print("snapchat")
                        if 'gena' in y.keys():
                            if b'com.snapchat.keyservice.persistedkey' == y['gena']:
                                # print("persisted")
                                # print(y['v_Data'])
                                persisted = y['v_Data']
                            elif b'egocipher.key.avoidkeyderivation' == y['gena']:
                                egocipher = y['v_Data']
    except:
        try:  # Premium Keychain
            if "keychainEntries" in keychain_plist.keys():
                print("Decrypting UFED keychain")
                convert_keychain.main(keychain, "decrypted_keychain.plist")
                with open("decrypted_keychain.plist", "rb") as f:
                    keychain_plist = plistlib.load(f)
                for y in keychain_plist:
                    if 'agrp' in y.keys():
                        if y['agrp'] == "3MY7A92V5W.com.toyopagroup.picaboo" and 'gena' in y.keys():
                            if y['gena'] == b'com.snapchat.keyservice.persistedkey':
                                persisted = y['v_Data']
                            elif y['gena'] == b'egocipher.key.avoidkeyderivation':
                                egocipher = y['v_Data']
        except Exception as error:
            print("Could not read keychain, this is unexpected, contact author", error)
    if egocipher == "":
        print("Could not find correct key (egocipher) in keychain, please verify manually and contact the author if "
              "it is present")
    else:
        print("Found egocipher.key.avoidkeyderivation (Used for Memories)")
        
    if persisted != "":
        print("Found com.snapchat.keyservice.persistedkey (Used for MEO)")
        
    return egocipher, persisted


def main():
    global decryptedName
    global outputDir

    outputDir = "./Snapchat_Memories_report_" + datetime.today().strftime('%Y%m%d_%H%M%S')
    os.makedirs(outputDir + "//DecryptedMemories", exist_ok=True)

    enc_db = sys.argv[1]
    scdb = sys.argv[2]
    keychain = sys.argv[3]
    # egocipherKey = sys.argv[3]
    # try:
    #     persistedKey = sys.argv[4]
    # except:
    #     persistedKey = ""
    decryptedName = "gallery_decrypted.sqlite"


    start_date = promptDate("start")
    end_date = promptDate("end")

    egocipher, persisted = readKeychain(keychain)

    decryptGallery(enc_db, egocipher)
    # decryptGallery(enc_db, egocipherKey)

    recoverDatabase()

    df_MemoryKey = getMemoryKey(decryptedName + "_r")
    df_SCDBInfo = getFullSCDBInfo(scdb)
    df_merge = pd.merge(df_MemoryKey, df_SCDBInfo, on=["ID"])


    df_merge = filterDfByDates(df_merge, start_date, end_date)
    df_merge = df_merge.sort_values(by='ZCREATETIMEUTC', ascending=True)

    getMemoriesFromURL(df_merge)

    df_merge = decryptMemories(egocipher, persisted, df_merge)

    generateReport(df_merge)
    print(f"Report can be found in {outputDir}")
    print(f"Decrypted memories can be found in {outputDir}/DecryptedMemories")


if __name__ == "__main__":
    main()
