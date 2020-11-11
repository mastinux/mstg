
Java.perform(function () {
	try {
		var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase")

		SQLiteDatabase.execSQL
			.overload('java.lang.String')
			.implementation = function(sql){
				console.log(sql)

				return this.execSQL(sql)
			}
	}
	catch(e) {
		console.log(e.message);
	}
});

// sg.vp.owasp_mobile.omtg_android