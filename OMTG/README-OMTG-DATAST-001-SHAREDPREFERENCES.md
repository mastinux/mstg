## OMTG-DATAST-001-SHAREDPREFERENCES

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_SharedPreferences.java

```java
SharedPreferences.Editor edit = getSharedPreferences("key", 1).edit();

edit.putString("username", "administrator");
edit.putString("password", "supersecret");

edit.commit();
```

Exploit:

- `$ adb shell cat /data/user/0/sg.vp.owasp_mobile.omtg_android/shared_prefs/sg.vp.owasp_mobile.omtg_android_preferences.xml`
