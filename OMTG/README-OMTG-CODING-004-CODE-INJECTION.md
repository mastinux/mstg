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

\# FIXME

```
I ActivityManager: START u0 {cmp=sg.vp.owasp_mobile.omtg_android/sg.vp.owasp_mobile.OMTG_Android.OMTG_CODING_004_Code_Injection} from uid 10160
W System.err: java.lang.ClassNotFoundException: Didn't find class "com.example.CodeInjection" on path: DexPathList[[zip file "/storage/emulated/0/libcodeinjection.jar"],nativeLibraryDirectories=[/system/lib, /system/vendor/lib]]
W System.err: 	at dalvik.system.BaseDexClassLoader.findClass(BaseDexClassLoader.java:125)
W System.err: 	at java.lang.ClassLoader.loadClass(ClassLoader.java:379)
W System.err: 	at java.lang.ClassLoader.loadClass(ClassLoader.java:312)
W System.err: 	at sg.vp.owasp_mobile.OMTG_Android.OMTG_CODING_004_Code_Injection.onCreate(OMTG_CODING_004_Code_Injection.java:35)
W System.err: 	at android.app.Activity.performCreate(Activity.java:7009)
W System.err: 	at android.app.Activity.performCreate(Activity.java:7000)
W System.err: 	at android.app.Instrumentation.callActivityOnCreate(Instrumentation.java:1214)
W System.err: 	at android.app.ActivityThread.performLaunchActivity(ActivityThread.java:2731)
W System.err: 	at android.app.ActivityThread.handleLaunchActivity(ActivityThread.java:2856)
W System.err: 	at android.app.ActivityThread.-wrap11(Unknown Source:0)
W System.err: 	at android.app.ActivityThread$H.handleMessage(ActivityThread.java:1589)
W System.err: 	at android.os.Handler.dispatchMessage(Handler.java:106)
W System.err: 	at android.os.Looper.loop(Looper.java:164)
W System.err: 	at android.app.ActivityThread.main(ActivityThread.java:6494)
W System.err: 	at java.lang.reflect.Method.invoke(Native Method)
W System.err: 	at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:440)
W System.err: 	at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:807)
W System.err: 	Suppressed: java.io.IOException: No original dex files found for dex location /storage/emulated/0/libcodeinjection.jar
W System.err: 		at dalvik.system.DexFile.openDexFileNative(Native Method)
W System.err: 		at dalvik.system.DexFile.openDexFile(DexFile.java:353)
W System.err: 		at dalvik.system.DexFile.<init>(DexFile.java:100)
W System.err: 		at dalvik.system.DexFile.<init>(DexFile.java:74)
W System.err: 		at dalvik.system.DexPathList.loadDexFile(DexPathList.java:374)
W System.err: 		at dalvik.system.DexPathList.makeDexElements(DexPathList.java:337)
W System.err: 		at dalvik.system.DexPathList.<init>(DexPathList.java:157)
W System.err: 		at dalvik.system.BaseDexClassLoader.<init>(BaseDexClassLoader.java:65)
W System.err: 		at dalvik.system.DexClassLoader.<init>(DexClassLoader.java:54)
W System.err: 		at sg.vp.owasp_mobile.OMTG_Android.OMTG_CODING_004_Code_Injection.onCreate(OMTG_CODING_004_Code_Injection.java:34)
W System.err: 		... 13 more
```
