## OMTG-DATAST-001-SQLITE-ENCRYPTED

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_SQLite_Encrypted.java

```java
private void SQLiteEnc() {
	SQLiteDatabase.loadLibs(this);

	File database = getDatabasePath("encrypted");
	database.mkdirs();
	database.delete();

	SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, stringFromJNI(), null);

	secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
	secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
	secureDB.close();
}
```

Exploit:

- crea uno script Frida per fare l'hooking del metodo `SQLiteDatabase.openOrCreateDatabase()` in modo da recuperare la password

```javascript
Java.perform(function () {
    var sqliteDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");

    sqliteDatabase.openOrCreateDatabase
    	.overload('java.io.File', 'java.lang.String', 'net.sqlcipher.database.SQLiteDatabase$CursorFactory')
    	.implementation = function (file, password, factory) {

    		console.log("[+] database password: " + password)

	        retVal = this.openOrCreateDatabase(file, password, factory);

	        return retVal
    	};
});
```

N.B.: script Frida non verificato dato che l'app va in crash (`Abort message: 'java_vm_ext.cc:534] JNI DETECTED ERROR IN APPLICATION: unknown format specifier: 'R''`)
