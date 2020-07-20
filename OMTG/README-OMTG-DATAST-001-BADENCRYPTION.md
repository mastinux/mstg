## OMTG-DATAST-001-BADENCRYPTION

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_BadEncryption.java

```java
public static boolean verify(String str) {
	byte[] decode = Base64.decode("vJqfip28ioydips=", 0);
	byte[] encrypt = encrypt(str);
	
	if (encrypt.length != decode.length) {
		return false;
	}
	
	for (int i = 0; i < encrypt.length; i++) {
		if (encrypt[i] != decode[i]) {
			return false;
		}
	}
	
	return true;
}

private static byte[] encrypt(String str) {
	byte[] bytes = str.getBytes();
	
	for (int i = 0; i < bytes.length; i++) {
		bytes[i] = (byte) ((byte) (bytes[i] ^ Ascii.DLE));
		bytes[i] = (byte) ((byte) (bytes[i] & 255));
	}
	
	return bytes;
}
```

> com.google.common.base.Ascii

`Ascii.DLE = 16`

Exploit:

- la funzione `encrypt` fa uno XOR e il flip dei byte della stringa `vJqfip28ioydips=` decodificata

- esegui il seguente codice Java

```java
import java.util.Base64;

public class Main{
	private static String decrypt(byte[] bytes){
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) (bytes[i] ^ 16);
			bytes[i] = (byte) ((byte) (~bytes[i] & 255));
		}

		return new String(bytes);
	}

	public static void main(String []args){
		byte[] decoded = Base64.getDecoder().decode("vJqfip28ioydips=");
		System.out.println(decrypt(decoded));
	}
}
```
