## OMTG-NETW-004-SSL-PINNING-CERTIFICATE

> app/src/main/java/sg/vp/owasp_mobile/OMTG_NETW_004_SSL_Pinning_Certificate.java

```java
private void HTTPSssLPinning() 
		throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {

	CertificateFactory instance = CertificateFactory.getInstance("X.509");

	BufferedInputStream bufferedInputStream = 
		new BufferedInputStream(getResources().openRawResource(C0000R.raw.certificate));

	Certificate generateCertificate = instance.generateCertificate(bufferedInputStream);
	bufferedInputStream.close();

	KeyStore instance2 = KeyStore.getInstance(KeyStore.getDefaultType());
	instance2.load((InputStream) null, (char[]) null);
	instance2.setCertificateEntry("ca", generateCertificate);

	Enumeration<String> aliases = instance2.aliases();

	while (aliases.hasMoreElements()) {
		PrintStream printStream = System.out;

		printStream.println("KeyStore: " + aliases.nextElement().toString());
	}

	TrustManagerFactory instance3 = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	instance3.init(instance2);

	final SSLContext instance4 = SSLContext.getInstance("TLS");
	instance4.init((KeyManager[]) null, instance3.getTrustManagers(), (SecureRandom) null);

	new Thread(new Runnable() {
		public void run() {
			URL url;

			try {
				url = new URL("https://example.com");
			} catch (MalformedURLException e) {
				try {
					e.printStackTrace();

					url = null;
				} catch (IOException e2) {
					e2.printStackTrace();

					return;
				}
			}

			HttpsURLConnection httpsURLConnection = (HttpsURLConnection) url.openConnection();
			httpsURLConnection.setSSLSocketFactory(instance4.getSocketFactory());

			InputStream inputStream = httpsURLConnection.getInputStream();

			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));

			while (true) {
				String readLine = bufferedReader.readLine();

				if (readLine != null) {
					System.out.println(readLine);
				} else {
					inputStream.close();

					return;
				}
			}
		}
	}).start();
}
```

Exploit:

- \# TODO