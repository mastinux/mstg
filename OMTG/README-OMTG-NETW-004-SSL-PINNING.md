## OMTG-NETW-004-SSL-PINNING

> app/src/main/java/sg/vp/owasp_mobile/OMTG_NETW_004_SSL_Pinning.java

```java
public void onCreate(Bundle bundle) {
	super.onCreate(bundle);

	setContentView((int) C0000R.layout.activity_omtg__netw_004__ssl__pinning);
	setSupportActionBar((Toolbar) findViewById(C0000R.id.toolbar));

	new Thread(new Runnable() {
		public void run() {
			try {
				new SSLPinning().onCreate();

				BufferedReader bufferedReader = new BufferedReader(
					new InputStreamReader(
						((HttpsURLConnection) new URL("https://www.example.com")
							.openConnection())
						.getInputStream()));

				while (true) {
					String readLine = bufferedReader.readLine();

					if (readLine != null) {
						System.out.println(readLine);
					} else {
						bufferedReader.close();

						return;
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}).start();
}
```

> app/src/main/java/sg/vp/owasp_mobile/SSLPinning.java

```java
public class SSLPinning {
	public void onCreate() {
		try {
			SSLContext instance = SSLContext.getInstance("TLS");
			instance.init(null, new TrustManager[]{new HardenedX509TrustManager(null)}, null);
			
			HttpsURLConnection.setDefaultSSLSocketFactory(instance.getSocketFactory());
		} catch (NoSuchAlgorithmException unused) {
			System.exit(-1);
		} catch (KeyManagementException unused2) {
			System.exit(-1);
		} catch (KeyStoreException unused3) {
			System.exit(-1);
		}
	}
}
```

> app/src/main/java/sg/vp/owasp_mobile/HardenedX509TrustManager.java

```java
public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
	this.standardTrustManager.checkServerTrusted(x509CertificateArr, str);
	
	int length = x509CertificateArr.length;
	int i = 0;
	
	while (i < length) {
		String name = x509CertificateArr[i].getIssuerDN().getName();
		
		if (name.indexOf(",O=PortSwigger,") != -1) {
			Log.w("Error", name);
			i++;
		} else {
			throw new CertificateException();
		}
	}
}
```

Exploit:

- inietta il seguente script tramite frida per impedire che venga lanciata l'exception CertificateException nel metodo checkServerTrusted() della classe HardenedX509TrustManager

```javascript
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
```

- `$ adb logcat`

```
I System.out: <!doctype html>
I System.out: <html>
I System.out: <head>
I System.out:     <title>Example Domain</title>
I System.out:     <meta charset="utf-8" />
I System.out:     <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
I System.out:     <meta name="viewport" content="width=device-width, initial-scale=1" />
I System.out:     <style type="text/css">
I System.out:     body {
I System.out:         background-color: #f0f0f2;
I System.out:         margin: 0;
I System.out:         padding: 0;
I System.out:         font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
I System.out:         
I System.out:     }
I System.out:     div {
I System.out:         width: 600px;
I System.out:         margin: 5em auto;
I System.out:         padding: 2em;
I System.out:         background-color: #fdfdff;
I System.out:         border-radius: 0.5em;
I System.out:         box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
I System.out:     }
I System.out:     a:link, a:visited {
I System.out:         color: #38488f;
I System.out:         text-decoration: none;
I System.out:     }
I System.out:     @media (max-width: 700px) {
I System.out:         div {
I System.out:             margin: 0 auto;
I System.out:             width: auto;
I System.out:         }
I System.out:     }
I System.out:     </style>    
I System.out: </head>
I System.out: <body>
I System.out: <div>
I System.out:     <h1>Example Domain</h1>
I System.out:     <p>This domain is for use in illustrative examples in documents. You may use this
I System.out:     domain in literature without prior coordination or asking for permission.</p>
I System.out:     <p><a href="https://www.iana.org/domains/example">More information...</a></p>
I System.out: </div>
I System.out: </body>
I System.out: </html>
```
