
Java.perform(function () {
	try {
		var webView = Java.use("android.webkit.WebView")

		webView.loadUrl
			.overload('java.lang.String')
			.implementation = function(url) {
				console.log(url)

				return this.loadUrl(url)
			}
	}
	catch(e) {
		console.log(e.message);
	}
});

// sg.vp.owasp_mobile.omtg_android