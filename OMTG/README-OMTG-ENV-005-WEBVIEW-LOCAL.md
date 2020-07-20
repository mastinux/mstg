## OMTG-ENV-005-WEBVIEW-LOCAL

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Local.java

```java
myWebView.getSettings().setJavaScriptEnabled(true);

myWebView.getSettings().setAllowFileAccessFromFileURLs(true);

myWebView.addJavascriptInterface(new JavaScriptInterface(), "jsinterface");

myWebView.loadUrl("file:///android_asset/local.htm");
```

Exploit:

- l'exploit è possibile su Android 4.1 o inferiori (CVE-2012-6636)

- estrai il file `local.htm` dalla directory `assets/` nell'apk `/data/app/<package-name>/base.apk` 

- implementa uno script Frida per fare l'hooking di `android.webkit.WebView` al fine di stampare tutte le URL caricate tramite WebView e identificare i metodi degli oggetti Java accessibili da JavaScript tramite cui puoi eseguire codice arbitrario a livello Java
