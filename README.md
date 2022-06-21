# Snap_DecryptMemories
Script to download and decrypt memories and MEO from Snapchat on IOS. Requires the keys for memories to be present in the keychain, as well as the MEO key to get the MEO content.

After decrypting the database, it must be repaired. If you have SQLite3 installed on your system it will perform the repair, if not you requires any other way to fix a broken database; personal preference is Sanderssons Sqlite forensics tool https://sqliteforensictoolkit.com/ but other tools that renders the database viewable should also function.



|Application|Key|Base64 string|
|---|---|---|
|Snapchat Memories|egocipher.key.avoidkeyderivation|ZWdvY2lwaGVyLmtleS5hdm9pZGtleWRlcml2YXRpb24=|
|Snapchat My Eyes Only|com.snapchat.keyservice.persistedkey|Y29tLnNuYXBjaGF0LmtleXNlcnZpY2UucGVyc2lzdGVka2V5|




Run via CMD
DecryptMemories.py [gallery_encrypteddb] [scdb-27.sqlite3] [egocipherkey] \<optional-persistedkey\>

Program will prompt you to open the decrypted database in forensic browser; do so before continuing.

IF YOU USE ANY OTHER PROGRAM THAN SANDERSON FORENSIC BROWSER FOR SQLITE: the script is looking for a file named "gallery_decrypted.sqlite_r" which is the default name given in sandersons. Using anything else will necessitate you to rename the file.

Any questions just DM Cygonaut#7609 on Discord
