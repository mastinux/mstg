## OMTG-DATAST-002-LOGGING

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_002_Logging.java

```java
String str3 = this.TAG;

Log.e(str3, "User successfully logged in. User: " + str + " Password: " + str2);
System.out.println("WTF, Logging Class should be used instead.");

Toast.makeText(this, "Log output has been created", 1).show();
```

Exploit:

- `$ adb logcat`

```
06-04 15:59:55.793  3010  3010 E OMTG_DATAST_002_Logging: User successfully logged in. User: my-username Password: my-password
```