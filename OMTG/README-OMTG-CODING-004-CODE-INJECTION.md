## OMTG-CODING-004-CODE-INJECTION

> app/src/main/java/sg/vp/owasp_mobile/OMTG_CODING_004_Code_Injection.java

```java
public void onCreate(Bundle bundle) {
	super.onCreate(bundle);

	setContentView((int) C0000R.layout.activity_omtg__coding_004__code__injection);
	setSupportActionBar((Toolbar) findViewById(C0000R.id.toolbar));
	getSupportActionBar().setDisplayHomeAsUpEnabled(true);

	try {
		Class loadClass = new DexClassLoader(
				Environment.getExternalStorageDirectory() + "/libcodeinjection.jar", 
				getDir("dex", 0).getAbsolutePath(), 
				(String) null, 
				getClass().getClassLoader())
			.loadClass("com.example.CodeInjection");

		Log.e(
			"Test", 
			(String) loadClass.getMethod(
				"returnString", 
				new Class[0]).invoke(loadClass.newInstance(), 
				new Object[0]));

	} catch (Exception e) {
		e.printStackTrace();
	}
}
```

`$ adb logcat`

```
I ActivityManager: START u0 {cmp=sg.vp.owasp_mobile.omtg_android/sg.vp.owasp_mobile.OMTG_Android.OMTG_CODING_004_Code_Injection} from uid 10160
W System  : ClassLoader referenced unknown path: /storage/emulated/0/libcodeinjection.jar
W System.err: java.lang.ClassNotFoundException: Didn't find class "com.example.CodeInjection" on path: DexPathList[[],nativeLibraryDirectories=[/system/lib, /system/vendor/lib]]
```

Exploit:

- crea un .jar che abbia una classe `com.example.CodeInjection` con un metodo `returnString`

- copia il .jar in /sdcard

