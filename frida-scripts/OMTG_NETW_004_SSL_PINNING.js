Java.perform(function () {
	try {
		var x509TrustManager = Java.use("sg.vp.owasp_mobile.OMTG_Android.HardenedX509TrustManager")
		
		x509TrustManager.checkServerTrusted
			.implementation = function(arr, str) {
				console.log("bypassing issuerDN checks")
			
				return
			}
	}
	catch(e) {
		console.log(e.message);
	}
});

// sg.vp.owasp_mobile.omtg_android
