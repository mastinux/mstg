## OMTG-DATAST-001-KEYSTORE

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_KeyStore.java

```java
KeyPairGeneratorSpec keyPairGeneratorSpec = null;

if (Build.VERSION.SDK_INT >= 18) {
	keyPairGeneratorSpec = new KeyPairGeneratorSpec
		.Builder(this)
		.setAlias("Dummy")
		.setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
		.setSerialNumber(BigInteger.ONE)
		.setStartDate(instance.getTime())
		.setEndDate(instance2.getTime())
		.build();
}

KeyPairGenerator instance3 = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");

instance3.initialize(keyPairGeneratorSpec);

instance3.generateKeyPair();

...

RSAPublicKey rSAPublicKey = (RSAPublicKey) ((KeyStore.PrivateKeyEntry) this
	.keyStore.getEntry(str, null)).getCertificate().getPublicKey();

String str2 = this.TAG;

Log.v(str2, "test log: " + "12345678");
Log.e(this.TAG, String.valueOf(rSAPublicKey));

String obj = this.startText.getText().toString();

if (obj.isEmpty()) {
	Toast.makeText(this, "Enter text in the 'Initial Text' widget", 1).show();

	return;
}

Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
instance.init(1, rSAPublicKey);

ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, instance);
cipherOutputStream.write(obj.getBytes(StringEncodings.UTF8));
cipherOutputStream.close();

byte[] byteArray = byteArrayOutputStream.toByteArray();

this.encryptedText.setText(Base64.encodeToString(byteArray, 0));

...

KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) this
	.keyStore.getEntry(str, null);

Log.e(this.TAG, String.valueOf(privateKeyEntry.getPrivateKey().getEncoded()));

Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
instance.init(2, privateKeyEntry.getPrivateKey());

CipherInputStream cipherInputStream = new CipherInputStream(
	new ByteArrayInputStream(Base64.decode(
		this.encryptedText.getText().toString(), 0)), instance);

ArrayList arrayList = new ArrayList();

while (true) {
	int read = cipherInputStream.read();

	if (read == -1) {
		break;
	}

	arrayList.add(Byte.valueOf((byte) read));
}

byte[] bArr = new byte[arrayList.size()];

for (int i = 0; i < bArr.length; i++) {
	bArr[i] = ((Byte) arrayList.get(i)).byteValue();
}

this.decryptedText.setText(new String(bArr, 0, bArr.length, StringEncodings.UTF8));
```

Le coppie di chiavi generate tramite il `Keystore` vengono memorizzate in `/data/misc/keystore/user_0`.
I file che le contengono sono cifrati.

Il codice mostra un esempio di implementazione dell'uso dell'Android Keystore che ne impedisce l'estrazione.

Exploit:

- NONE