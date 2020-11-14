## OMTG-ENV-005-WEBVIEW-REMOTE

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Remote.java

```java
webSettings.setJavaScriptEnabled(true);

myWebView.addJavascriptInterface(jsInterface, "Android");

myWebView.loadUrl("https://rawgit.com/sushi2k/AndroidWebView/master/webview.htm");
```

> https://rawgit.com/sushi2k/AndroidWebView/master/webview.htm

```javascript
//check if JavaScript is activated
alert(43);

var file = "file://storage/emulated/0/password.txt";
var xhr = new XMLHttpRequest();
xhr.overrideMimeType("text/plain; charset=iso-8859-1");
xhr.open("GET", file, true);
xhr.onreadystatechange = function() {
	var data = xhr.responseText;
	// alert(data);
}
xhr.send();

var result = window.Android.returnString();
document.getElementById("p1").innerHTML = result;

function fireToastMessage() {
	window.Android.showToast("this is executed by JavaScript"); 
}
```

I metodi Java `returnString()` e `showToast(String toast)` sono invocati usando il bridge JavaScript WebView (`Android`) per rivelare testo nascosto e per mostrare un toast nell'app.

Exploit:

- inietta il seguente script tramite frida per recuperare le URL caricate tramite WebView e identificare i metodi degli oggetti Java accessibili da JavaScript tramite cui puoi eseguire codice arbitrario a livello Java

```javascript
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
```