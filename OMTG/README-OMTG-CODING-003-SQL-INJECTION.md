## OMTG-CODING-003-SQL-Injection

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_CODING_003_SQL_Injection.java

```java
private boolean checkLogin(String username, String password) {
	boolean bool = false;

	SQLiteDatabase authentication = openOrCreateDatabase("authentication", MODE_PRIVATE, null);

	try (Cursor cursor = 
		authentication.rawQuery("SELECT * FROM Accounts WHERE Username = '" + username + "' and Password = '" + password + "';", null)) {

		if (cursor != null) {
			if (cursor.moveToFirst())
				bool = true;

			cursor.close();
		}
	} catch (Exception e) {
		e.printStackTrace();
	}

	return bool;
}
```

- il modo in cui la query al database viene costruita è vulnerabile a SQL Injection

Exploit:

- `$ adb shell input text "a' or 'a'='a"`