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

Exploit:

- i metodi Java `returnString()` e `showToast(String toast)` sono invocati usando il bridge JavaScript WebView (`Android`) per rivelare testo nascosto e per mostrare un toast nell'app

- implementa uno script Frida per fare l'hooking di `android.webkit.WebView` al fine di stampare tutte le URL caricate tramite WebView e identificare i metodi degli oggetti Java accessibili da JavaScript tramite cui puoi eseguire codice arbitrario a livello Java