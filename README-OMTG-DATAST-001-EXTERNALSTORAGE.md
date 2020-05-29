## OMTG-DATAST-001-EXTERNALSTORAGE

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_ExternalStorage.java

```
FileOutputStream fileOutputStream = new FileOutputStream(
	new File(Environment.getExternalStorageDirectory(), "password.txt"));
fileOutputStream.write("L33tS3cr3t".getBytes());
fileOutputStream.close();
```

Exploit:

- `$ adb shell cat /sdcard/password.txt`

