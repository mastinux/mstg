## OMTG-DATAST-011-MEMORY

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
	...

	decryptString();
}

public void decryptString() {
	SecretKeys privateKey = null;

	try {
		privateKey = AesCbcWithIntegrity.keys("4zInk+d4jlQ3m1B1ELctxg==:4aZtzwpbniebvM7yC4/GIa2ZmJpSzqrAFtVk91Rm+Q4=");
	} catch (InvalidKeyException e) {
		e.printStackTrace();
	}

	try {
		this.plainText = AesCbcWithIntegrity
			.decryptString(
				new CipherTextIvMac(
					"6WpfZkgKMJsPhHNhWoSpVg==:6/TgUCXrAuAa2lUMPWhx8hHOWjWEHFp3VIsz3Ws37ZU=:C0mWyNQjcf6n7eBSFzmkXqxdu55CjUOIc5qFw02aVIfQ1CI8axsHijTJ9ZW6ZfEE"), 
				privateKey);
	} catch (UnsupportedEncodingException e2) {
		e2.printStackTrace();
	}
	catch (GeneralSecurityException e3) {
		e3.printStackTrace();
	}
}
```

Exploit:

- avvia l'app e apri 

- usa fridump.py

```sh
$ python fridump.py -U -s sg.vp.owasp_mobile.omtg_android
```

- analizzando il file `dump/strings.txt` generato, troverai `U got the decrypted message. Well done.`

oppure

- inietta il seguente script tramite frida per intercettare il valore decifrato

```javascript
Java.perform(function () {
	try {

		var aesCbcWithIntegrity = Java.use("com.tozny.crypto.android.AesCbcWithIntegrity")

		aesCbcWithIntegrity
			.decryptString
			.overload('com.tozny.crypto.android.AesCbcWithIntegrity$CipherTextIvMac', 'com.tozny.crypto.android.AesCbcWithIntegrity$SecretKeys')
			.implementation = function(arg1, arg2){

				var retVal = this.decryptString(arg1, arg2)

				console.log(retVal)

				return retVal
			}

	}
	catch(e) {
		console.log(e.message);
	}
});
```