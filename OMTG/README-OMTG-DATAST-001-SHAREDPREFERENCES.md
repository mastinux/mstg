## OMTG-DATAST-001-SHAREDPREFERENCES

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_SharedPreferences.java

```java
SharedPreferences.Editor edit = 
	getSharedPreferences("key", 1).edit();

edit.putString("username", "administrator");
edit.putString("password", "supersecret");

edit.commit();
```

Exploit:

- `$ adb shell cat /data/user/0/sg.vp.owasp_mobile.omtg_android/shared_prefs/sg.vp.owasp_mobile.omtg_android_preferences.xml`

oppure

- inietta il seguente script tramite frida per intercettare i valori salvati nelle SharedPreferences

```javascript
Java.perform(function () {
        try {
                var editorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

                editorImpl.putString
                        .overload('java.lang.String', 'java.lang.String')
                        .implementation = function (key, value) {
                                console.log(key + ": " + value)

                                return this.putString(key, value)
                        }
        }
        catch(e) {
                console.log(e.message);
        }

});
```