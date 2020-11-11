
Java.perform(function () {
    var sqliteDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");

    sqliteDatabase.openOrCreateDatabase
    	.overload('java.io.File', 'java.lang.String', 'net.sqlcipher.database.SQLiteDatabase$CursorFactory')
    	.implementation = function (file, password, factory) {

    		console.log("database password: " + password)

	        return this.openOrCreateDatabase(file, password, factory)
    	};
});

// sg.vp.owasp_mobile.omtg_android