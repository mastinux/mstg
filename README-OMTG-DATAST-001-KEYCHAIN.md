## OMTG-DATAST-001-KEYCHAIN

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_KeyChain.java

```
public static final String PKCS12_FILENAME = "server.p12";

...

BufferedInputStream bufferedInputStream = new BufferedInputStream(getAssets().open(PKCS12_FILENAME));

byte[] bArr = new byte[bufferedInputStream.available()];
bufferedInputStream.read(bArr);

Intent createInstallIntent = KeyChain.createInstallIntent();
createInstallIntent.putExtra("PKCS12", bArr);

startActivity(createInstallIntent);
```

Exploit:

- nessuno, mostra una best practice per importare un certificato nella KeyChain

