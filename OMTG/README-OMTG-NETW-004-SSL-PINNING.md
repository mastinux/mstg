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

Exploit:

- \# TODO