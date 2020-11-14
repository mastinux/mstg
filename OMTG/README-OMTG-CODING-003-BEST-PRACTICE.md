## OMTG-CODING-003-BEST-PRACTICE

> app/src/main/java/sg/vp/owasp_mobile/OMTG_Android/OMTG_CODING_003_Best_Practice.java

```java
...

private void initializeDB(Context applicationContext) {
	File dbAvailable;

	dbAvailable = applicationContext.getDatabasePath("authentication-best-practice");

	if (!dbAvailable.exists()) {
		SQLiteDatabase authentication = openOrCreateDatabase("authentication-best-practice", MODE_PRIVATE, null);

		authentication.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
		authentication.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");

		authentication.close();
	}
}

...

private boolean checkLogin(String username, String password) {
	boolean bool = false;
	SQLiteDatabase authentication = openOrCreateDatabase("authentication-best-practice", MODE_PRIVATE, null);

	try (Cursor cursor = authentication.rawQuery("SELECT * FROM Accounts WHERE Username=? and Password=?", new String[] {username,password})) {
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

...
```

Exploit:

- nessuno, mostra una best practice per evitare una SQL injection nel metodo `checkLogin()`

- tuttavia le credenziali di accesso sono hardcoded nel metodo `initializeDB()`