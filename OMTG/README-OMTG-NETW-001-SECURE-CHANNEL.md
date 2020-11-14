## OMTG-NETW-001-SECURE-CHANNEL

> app/src/main/java/sg/vp/owasp_mobile/OMTG_NETW_001_Secure_Channel.java

```java
public void onCreate(Bundle bundle) {
	super.onCreate(bundle);

	setContentView((int) C0000R.layout.activity_omtg__netw_001__secure__channel);
	setSupportActionBar((Toolbar) findViewById(C0000R.id.toolbar));
	getSupportActionBar().setDisplayHomeAsUpEnabled(true);

	((WebView) findViewById(C0000R.id.webView1)).loadUrl(getResources().getString(C0000R.string.url_example));

	((WebView) findViewById(C0000R.id.webView2)).loadUrl(getResources().getString(C0000R.string.url_example_ssl));
}
```

Exploit:

- nessuno, la prima chiamata a `loadUrl()` carica una pagina web con http, la seconda invece con https.
Nel primo caso può essere facilmente intercettata da un attaccante