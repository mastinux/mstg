
Java.perform(function () {
	try {
		var cipher = Java.use("javax.crypto.Cipher")

		cipher.init.implementation = function(opmode, key){
			this.init(opmode, key)
		}

	}
	catch(e) {
		console.log(e.message);
	}
});

// sg.vp.owasp_mobile.omtg_android