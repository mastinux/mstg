## OMTG-DATAST-005-KEYBOARD-CACHE

> app/src/main/res/layout/content_omtg__datast_005__keyboard__cache.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout ...>

    ...

    <EditText
        android:id="@+id/KeyBoardCache"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_centerHorizontal="true"
        android:layout_below="@id/KeyBoardCacheTextView"
        android:inputType="textNoSuggestions"
        android:hint="@string/title_activity_omtg__datast_052__keyboard_cache"/>


</RelativeLayout>
```

Exploit:

- nessuno, mostra come disattivare i suggerimenti da tastiera per EditText tramite `textNoSuggestions`
