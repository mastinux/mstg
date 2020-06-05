## OMTG-DATAST-001-SQLITE-ENCRYPTED

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_SQLite_Encrypted.java

```java
SQLiteDatabase.loadLibs(this);

File databasePath = getDatabasePath("encrypted");
databasePath.mkdirs();
databasePath.delete();

SQLiteDatabase openOrCreateDatabase = SQLiteDatabase.openOrCreateDatabase(databasePath, stringFromJNI(), (SQLiteDatabase.CursorFactory) null);

openOrCreateDatabase.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
openOrCreateDatabase.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");

openOrCreateDatabase.close();
```

Exploit:

- nessuno, il database viene cifrato con una stringa ottenuta dalla funzione `stringFromJNI()`

