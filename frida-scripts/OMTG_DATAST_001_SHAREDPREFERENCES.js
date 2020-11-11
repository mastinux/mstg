
Java.perform(function () {
	try {
		var editorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

		editorImpl.putString
			.overload('java.lang.String', 'java.lang.String')
			.implementation = function (key, value) {
				console.log(key + ": " + value)

				return this.putString(key, value)
			}
	}
	catch(e) {
		console.log(e.message);
	}

});

// sg.vp.owasp_mobile.omtg_android