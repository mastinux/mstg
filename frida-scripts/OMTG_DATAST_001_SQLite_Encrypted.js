
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

// sg.vp.owasp_mobile.omtg_android