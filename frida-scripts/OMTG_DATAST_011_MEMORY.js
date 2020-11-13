
Java.perform(function () {
	try {

		var aesCbcWithIntegrity = Java.use("com.tozny.crypto.android.AesCbcWithIntegrity")

		aesCbcWithIntegrity
			.decryptString
			.overload('com.tozny.crypto.android.AesCbcWithIntegrity$CipherTextIvMac', 'com.tozny.crypto.android.AesCbcWithIntegrity$SecretKeys')
			.implementation = function(arg1, arg2){

				var retVal = this.decryptString(arg1, arg2)

				console.log(retVal)

				return retVal
			}

	}
	catch(e) {
		console.log(e.message);
	}
});

// sg.vp.owasp_mobile.omtg_android