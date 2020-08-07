# Android Platform APIs

## Testing App Permissions (MSTG-PLATFORM-1)

Android assegna una system identity diversa (user ID e group ID Linux) a ogni app installata.
Poichè ogni app Android opera in una sandbox, le app devono chiedere esplicitamente accesso alle risorse e ai dati che sono al di fuori della propria sandbox.
Richiedono quest'accesso dichiarando i permessi di cui hanno bisogno per usare questi dati e feature di sistema.
In base a quanto i dati o le feature richiesti sono sensibili o critici, il sistema Android darà i permessi in modo automatico o chiederà l'approvazione all'utente.

I permessi Android sono classificati in quattro diverse categorie sulla base del livello di protezione che offrono:

- Normal: 
questa permission dà all'app accesso a feature isolate ad app-level con rischio minimo per le altre app, l'utente e il sistema
- Dangerous: 
questa permission di solito dà all'app il controllo sui dati utente o il controllo sul device per tutto ciò che riguarda l'utente stesso
- Signature: 
la permission viene data solo se l'app richiedente è firmata con lo stesso certificato usato per firmare l'app che ha dichiarato la permission.
Se la firma è verificata, la permission viene data automaticamente
- SystemOrSignature: 
questa permission viene data solo alle app embedded nella system image o firmate con lo stesso certificato usato per firmare l'app che ha dichiarato la permission

#### Activity Permission Enforcement

Le permission sono applicate tramite l'attributo `android:permission` nel tag `<activity>` nel manifest.
Queste permission restringono le applicazioni che possono lanciare l'activity.
Queste permission vengono verificate durante `Context.startActivity` e `Activity.startActivityForResult`.
Se non si posseggono le permission richieste viene lanciata una `SecurityException`.

#### Service Permission Enforcement

Le permission applicate tramite l'attributo `android:permission` nel tag `<service>` nel manifest restringono chi può avviare o agganciarsi al service.
La permission viene verificata durante `Context.startService`, `Context.stopService` e `Context.bindService`.
Se non si posseggono le permission richieste viene lanciata una `SecurityException`.

#### Broadcast Permission Enforcement

Le permission applicate tramite l'attributo `android:permission` nel tag `<receiver>` restringono chi può inviare messaggi broadcast al `BroadcastReceiver`.
Le permission vengono verificate dopo che il metodo `Context.sendBroadcast` è terminato.
Se non si posseggono le permission richieste tuttavia non viene lanciata un'exception, ma semplicemente il messaggio broadcast non viene inviato.

Una permission può essere passata al `Context.registerReceiver` per controllare chi può inviare messaggi broadcast verso un receiver registrato a livello di codice.
Diversamente, una permission può essere fornita alla chiamata di `Context.sendBroadcast` per restringere quali broadcast receiver possono ricevere il messaggio broadcast.

Nota che sia un receiver che un broadcaster possono richiedere una permission.
In questo caso, entrambi i controlli di permission devono essere verificati per l'intent per poter essere associato al target.

#### Content Provider Permission Enforcement

Le permission applicate tramite l'attributo `android:permission` nel tag `<provider>` restringono l'accesso ai dati di un ContentProvider.
I content provider hanno un'importante facility aggiuntiva di sicurezza chiamata URI permission.
Diversamente dagli altri componenti, i ContentProvider hanno due attributi di permission separati che possono essere impostati,
`android:readPermission` restringe chi può leggere dal provider,
e `android:writePermission` restringe chi può scrivere su di esso.
Se un ContentProvider è protetto sia con permessi di lettura che di scrittura, il possesso del solo permesso di scrittura non dà anche i permessi di lettura.

Queste permission sono date quando si recupera un provider (se non si ha la permission, viene lanciata una `SecurityException`), o quando si eseguono operazioni sul provider.
L'uso di `ContentResolver.query` richiede il possesso dei permessi di lettura;
L'uso di `ContentResolver.insert`, `ContentResolver.update` e `ContentResolver.delete` richiede il possesso dei permessi di scrittura.
Viene lanciata una `SecurityException` se non si posseggono le permission adeguate.

#### Content Provider URI Permissions

Il sistema standard di permission non è sufficiente quando viene usato con i content provider.
Per esempio un content provider potrebbe limitare le permission alla sola lettura per proteggersi, usando URI custom per recuperare informazioni.
Un app dovrebbe avere solo le permission per quella specifica URI.

La soluzione sono le permission per-URI.
Quando si avvia o si restiuisce il risutato di un'activity, il metodo può impostare `Intent.FLAG_GRANT_READ_URI_PERMISSION` e/o `Intent.FLAG_GRANT_WRITE_URI_PERMISSION`.
In questo modo si dà la permission all'activity per la specifica URI indipendentemente se ha le permission per accedere ai dati dal content provider.
Si realizza un modello comune secondo capability in cui le interazioni dell'utente portano alla concessione ad-hoc di permission fine-grained.
Ciò può ridurre le permission richieste dalle app a quelle direttamente collegate al loro comportamento.
Senza l'impiego di questo modello, utenti malevoli potrebbero accedere agli allegati di email di altri membri o recuperare una lista di contatti tramite URI non protette.
Nel manifest l'attributo `android:grantUriPermissions` o il node aiutano a restringere le URI.

#### Custom Permissions

Android consente alle app di esporre i propri service/component ad altre app.
Le custom permission sono necessarie per accedere ai componenti esposti dall'app.
Puoi definire custom permission nell'`AndroidManifest.xml` creando un tag permission con due attributi obbligatori: `android:name` e `android:protectionLevel`.

É cruciale creare custom permission che aderiscano al Principle of Least Privilege: la permission andrebbe definita esplicitamente per il suo scopo, con una label e una descrizione significativa e accurata.

### Static Analsysis

Controlla le permission per assicurarti che l'app ne abbia effettivamente bisogno e rimuovi quelle non necessarie.
Per esempio, la permission `INTERNET` nel file AndroidManifest.xml è necessaria per un Activity di caricamento di una pagina web in una WebView.
Dato che un utente può revocare una permission dangerous per un'app, lo sviluppatore dovrebbe controllare se l'app ha le permission appropriate ogni volta che un action che richiede la permission viene eseguita.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Analizza le permission insieme allo sviluppatore per identificare il motivo del loro utilizzo e rimuovi quelle non necessarie.
Oltre ad analizzare manualmente il file AndroidManifest.xml, puoi usare il Android Asset Packaging Tool per esaminare le permission.

```sh
$ aapt d permissions com.owasp.mstg.myappp
uses-permission: android.permission.WRITE_CONTACTS
uses-permission: android.permission.CHANGE_CONFIGURATION
uses-permission: android.permission.SYSTEM_ALERT_WINDOW
uses-permission: android.permission.INTERNAL_SYSTEM_WINDOW
```

\# FIXME prova comando aapt

#### Custom Permissions

Oltre a imporre delle permission custom tramite il file AndroidManifest.xml, puoi anche controllare le permission a livello di codice.
Questo approccio non è raccomandato, perchè è error-prone e può essere raggirato più facilmente, ad esempio tramite runtime instrumentation.
Si raccomanda di invocare il metodo `ContextCompat.checkSelfPermission` per controllare se un'activity ha una permission specifica.
Quando trovi del codice come quello che segue, assicurati che le stesse permission siano imposte nel file AndroidManifest.xml.

```java
private static final String TAG = "LOG";

int canProcess = checkCallingOrSelfPermission("com.example.perm.READ_INCOMING_MSG");

if (canProcess != PERMISSION_GRANTED)
	throw new SecurityException();
```

Oppure col metodo `ContextCompat.checkSelfPermission` che fa un confronto col contenuto del file AndroidManifest.xml.

```java
if (ContextCompat.checkSelfPermission(secureActivity.this, Manifest.READ_INCOMING_MSG)
	!= PackageManager.PERMISSION_GRANTED) {
		//!= stands for not equals PERMISSION_GRANTED
		Log.v(TAG, "Permission denied");
}
```

#### Requesting Permissions

Se l'app ha delle permission che devono essere richieste a runtime, deve invocare il metodo `requestPermissions` per ottenerle.
L'app passa le permission necessarie e un codice di richiesta che il programmatore ha specificato all'utente asincronamente, il processo termina una volta che l'utente ha accettato o rifiutato la richiesta.
Dopo che la risposta viene restituita lo stesso codice di richiesta viene passato alla callback dell'app.

```java
private static final String TAG = "LOG";

// We start by checking the permission of the current Activity
if (ContextCompat.checkSelfPermission(secureActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
	!= PackageManager.PERMISSION_GRANTED) {
	// Permission is not granted
	// Should we show an explanation?
	if (ActivityCompat.shouldShowRequestPermissionRationale(secureActivity.this,
			//Gets whether you should show UI with rationale for requesting permission.
			//You should do this only if you do not have permission and the permission requested rationale is not communicated clearly to the user.
		Manifest.permission.WRITE_EXTERNAL_STORAGE)) {
			// Asynchronous thread waits for the users response.
			// After the user sees the explanation try requesting the permission again.
	} else {
		// Request a permission that doesn't need to be explained.
		ActivityCompat.requestPermissions(
			secureActivity.this, 
			new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, 
			MY_PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE);
		// MY_PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE will be the app-defined int constant.
		// The callback method gets the result of the request.
	}
} else {
	// Permission already granted debug message printed in terminal.
	Log.v(TAG, "Permission already granted.");
}
```

Nota che se devi fornire informazioni o spiegazioni all'utente, è necessario farlo prima della chiamata al metodo `requestPermissions`, dato che il dialog box non può essere modificato una volta invocato.

#### Handling Responses to Permission Requests

L'app deve fare l'override del metodo `onRequestPermissionsResult` per verificare se la permission è stata data.
Questo metodo riceve l'integer `requestCode` come parametro (che è lo stesso codice di richiesta che è stato creato in `requestPermissions`).
La seguente callback potrebbe usare `WRITE_EXTERNAL_STORAGE`.

```java
@Override //Needed to override system method onRequestPermissionsResult()
public void onRequestPermissionsResult(int requestCode, //requestCode is what you specified in requestPermissions()
	String permissions[], int[] permissionResults) {
		switch (requestCode) {
			case MY_PERMISSIONS_WRITE_EXTERNAL_STORAGE: {
				if (grantResults.length > 0
					&& permissionResults[0] == PackageManager.PERMISSION_GRANTED) {
						// 0 is a canceled request, if int array equals requestCode permission is granted.
				} else {
					// permission denied code goes here.
					Log.v(TAG, "Permission denied");
				}
				return;
			}
			// Other switch cases can be added here for multiple permission checks.
		}
}
```

Le permission dovrebbero essere richieste per ogni permission necessaria, anche se una permission simile dello stesso gruppo è già stata richiesta.
Per esempio se `READ_EXTERNAL_STORAGE` e `WRITE_EXTERNAL_STORAGE` sono presenti in AndroidManifest.xml ma solo la permission per `READ_EXTERNAL_STORAGE` viene data, allora quando viene richiesta la permission per `WRITE_EXTERNAL_STORAGE` viene subito approvata senza richiederla all'utente.
Questo avviene perchè le due permission appartengono allo stesso gruppo e non sono richieste esplicitamente.

#### Permission Analysis

Verifica sempre se l'app richiede permission di cui ha effettivamente bisogno.
Assicurati che non vengano richieste permission che non hanno a che fare con l'obiettivo dell'app.
Per esempio: un gioco single player che richiede accesso a `android:permission.WRITE_SMS`, potrebbe non essere una buona idea.

### Dynamic Analysis

Le permission per app già installate possono essere recuperate con Drozer.

```sh
dz> run app.package.info -a com.android.mms.service

...

Uses Permissions:
- android.permission.RECEIVE_BOOT_COMPLETED
- android.permission.READ_SMS
- android.permission.WRITE_SMS
- android.permission.BROADCAST_WAP_PUSH
- android.permission.BIND_CARRIER_SERVICES
- android.permission.BIND_CARRIER_MESSAGING_SERVICE
- android.permission.INTERACT_ACROSS_USERS
Defines Permissions:
- None
```

Quando le app Android expongono component IPC ad altre app, possono definire delle permission per controllare quali app possono accedere ai component.
Per le comunicazioni con un component protetto con una permission `normal` o `dangerous`, Drozer può essere configurato per includere le permission richieste:

```sh
$ drozer agent build --permission android.permission.REQUIRED_PERMISSION
```

Nota che questo metodo non può essere usato per permission di livello `signature` dato che Drozer dovrebbe essere firmato con il certificato usato per firmare l'app target.

Durante la dynamic analysis: verifica se la permission richiesta dall'app sia effettivamente necessaria all'app.

### Testing for Injection Flaws (MSTG-PLATFORM-2)

Le app Android possono esporre delle funzionalità attraverso URL scheme custom (che sono parte degli intent).
Possono esporre funzionalità a:

- altre app (tramite i meccanismi IPC, come intent, binder, Android Shared Memeory o broadcast receiver)
- l'utente (tramite l'user interface)

Nessuno degli input provenienti da queste entità può esssere considerato fidato;
deve essere validato e/o sanificato.
La validazione assicura l'elaborazione di soli dati che l'app si aspetta.
Se la validazione non viene imposta, qualsiasi input può essere inviato all'app, ciò potrebbe consentire a un attaccante o a un app malevola di sfruttare la funzionalità dell'app.

Le seguenti porzioni di codice sorgente dovrebbero essere controllate se una funzionalità dell'app è esposta:

- URL scheme custom:
verifica anche il test case "Testing Custom URL Schemes" per altri scenari
- meccanismi di IPC (intent, binder, Android Shared Memory o broadcaster receiver):
verifica anche il test case "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms" per altri scenari
- interfaccia utente

Un esempio di meccanismo di IPC vulnerabile è riportato di seguito.
Puoi usare ContentProvider per accedere alle informazioni del database, e puoi interrogare i service per vedere se ritornano dati.
Se i dati non vengono validati adeguatamente, il content provider potrebbe essere vulnerabile a SQL Injection.
Vediamo un'implementazione di ContentProvider vulnerabile.

```xml
<provider
	android:name=".OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation"
	android:authorities="sg.vp.owasp_mobile.provider.College">
</provider>
```

Ispezioniamo la funzione `query` in `OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.java`.

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection,String[] selectionArgs, String sortOrder) {
	SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
	qb.setTables(STUDENTS_TABLE_NAME);

	switch (uriMatcher.match(uri)) {
		case STUDENTS:
			qb.setProjectionMap(STUDENTS_PROJECTION_MAP);

			break;
		case STUDENT_ID:
			// SQL Injection when providing an ID
			qb.appendWhere( _ID + "=" + uri.getPathSegments().get(1));
			Log.e("appendWhere",uri.getPathSegments().get(1).toString());

			break;
		default:
			throw new IllegalArgumentException("Unknown URI " + uri);
	}

	if (sortOrder == null || sortOrder == ""){
		/**
		* By default sort on student names
		*/
		sortOrder = NAME;
	}

	Cursor c = qb.query(db, projection, selection, selectionArgs,null, null, sortOrder);
	
	/**
	* register to watch a content URI for changes
	*/
	c.setNotificationUri(getContext().getContentResolver(), uri);
	
	return c;
}
```

L'utente deve specificare un valore per STUDENT_ID per `content://sg.vp.owasp_mobile.provider.College/students`.
La query è comunque vulnerabile a SQL Injection.
Bisogna usare i prepared statement per proteggersi dalle SQL Injection, ma bisogna applicare ugualmente l'input validation in modo da elaborare solo input che l'app si aspetta.

Tutte le funzioni dell'app che ricevono dati provenienti dalla UI dovrebbero implementare l'input validation:

- per input da UI si può usare Android Saripaar v2
- per input da IPC o URL schema, bisogna creare una funzione di validazione.
Per esempio la seguente verifica se la stringa è alfanumerica

```java
public boolean isAlphaNumeric(String s){
	String pattern= "^[a-zA-Z0-9]*$";
	return s.matches(pattern);
}
```

Un'alternativa alle funzioni di validazione sono le type conversion, come ad esempio se ci si aspetta un intero si può usare `Integer.parseInt`.

### Dynamic Analysis

Il tester dovrebbe verificare manualmente gli input field con stringhe come `OR 1=1--` se ad esempio è stata individuata una vulnerabilità di local SQL Injection.
Su un device rooted, il comando `content` può essere usato per richiedere i dati da un content provider.
Il seguente comando interroga la funzione vulnerabile descritta prima.

```sh
# content query --uri content://sg.vp.owasp_mobile.provider.College/students
```

Le SQL Injection possono essere sfruttate con il seguente comando.
Infatti, invece di ottenere il solo record di Bob, puoi recuperare tutti i dati memorizzati.

```sh
# content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='Bob') OR 1=1--''"
```

## Testing for Fragment Injection (MSTG-PLATFORM-2)

L'Android SDK offre agli sviluppatori un modo per presentare una `Preference Activity` agli utenti, consentendo di estendere e adatarre questa classe astratta.
Questa classe analizza i campi dei dati extra di un intent, `PreferenceActivity.EXTRA_SHOW_FRAGMENT(:android:show_fragment)` e `PreferenceActivity.EXTRA_SHOW_FRAGMENT_ARGUMENTS(:android:show_fragment_arguments)`.
Il primo campo contiene il nome della classe `Fragment`, e il secondo contiene il bundle di input passato al `Fragment`.

Dato che `PreferenceActivity` usa la reflection per caricare il fragment, potrebbe essere caricata una classe arbitraria nel package o nell'Android SDK.
La classe caricata viene eseguita all'interno del context dell'app che esporta l'activity.
Sfruttando questa vulnerabilità, un attaccante può invocare fragment all'interno dell'app target o eseguire codice presente in altri costruttori delle classi.
Qualsiasi classe che sia passata all'intent e che non estenda la classe Fragment causerebbe una `java.lang.CastException`, ma il costruttore vuoto verrebbe eseguito prima che l'exception venga lanciata, consentendo al codice presente nel costruttore della classe di essere eseguito.

Per impedire questa vulnerabilità, un nuovo metodo chiamato `isValidFragment` è stato aggiunto in Android 4.4.
Consente agli sviluppatori di farne l'override e di definire i fragment che possono essere usati in questo contesto.
L'implementazione di default restituisce `true` nelle versioni precedenti ad Android 4.4;
lancia un'exception nelle versioni successive.

### Static Analysis

Passi:

- controlla se `android:targetSdkVersion` è inferiore a 19
- individua le activity esportate che estendono la classe `PreferenceActivity`
- verifica se il metodo `isValidFragment` è stato sovrascritto
- se l'app imposta il suo `android:targetSdkVersion` nel manifest a un valore inferiore a 19 e la classe vulnerabile non contiene alcuna implementazione di `isValidFragment`, allora la vulnerabilità è ereditata da `PreferenceActivity`
- per rimediare, gli sviluppatori dovrebbero aggiornare `android:targetSdkVersion` a 19 o superiore.
Diversamente, se `android:targetSdkVersion` non può essere aggiornata, gli sviluppatori dovrebbero implementare `isValidFragment` come descritto prima

Il seguente esempio mostra un'activity che estende `PreferenceActivity`:

```java
public class MyPreferences extends PreferenceActivity {
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
	}
}
```

I seguenti esempi mostrano l'override del metodo `isValidFragment` con un'implementazione che consente il caricamento della sola classe `MyPreferenceFragment`:

```java
@Override
protected boolean isValidFragment(String fragmentName)
{
	return "com.fullpackage.MyPreferenceFragment".equals(fragmentName);
}
```

#### Example of Vulnerable App and Exploitation

MainActivity.class

```java
public class MainActivity extends PreferenceActivity {
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
	}
}
```

MyFragment.class

```java
public class MyFragment extends Fragment {
	public void onCreate (Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
	}

	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
		View v = inflater.inflate(R.layout.fragmentLayout, null);
		WebView myWebView = (WebView) wv.findViewById(R.id.webview);

		myWebView.getSettings().setJavaScriptEnabled(true);
		myWebView.loadUrl(this.getActivity().getIntent().getDataString());

		return v;
	}
}
```

Per sfruttare quest'activity vulnerabile, puoi creare un'app con il seguente codice:

```java
Intent i = new Intent();

i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);
i.setClassName("pt.claudio.insecurefragment","pt.claudio.insecurefragment.MainActivity");
i.putExtra(":android:show_fragment","pt.claudio.insecurefragment.MyFragment");

Intent intent = i.setData(Uri.parse("https://security.claudio.pt"));
startActivity(i);
```

## Testing Custom URL Schemes (MSTG-PLATFORM-3)

Sia Android che iOS consentono le comunicazioni tra app tramite URL schema custom.
Queste consentono alle altre app di eseguire specifiche azioni all'interno dell'app che offre l'URL schema custom.
Le URI custom possono avere un qualsiasi prefix, e di solito definiscono un action da eseguire all'interno dell'app e i suoi parametri.

Considera questo esempio inventato: `sms://compose/to=your.boss@company.com&message=I%20QUIT!&sendImmediately=true`.
Quando una vittima clicca su questo link da un device mobile, l'app vulnerabile invia un SMS con un contenuto malevolo.
Ciò potrebbe portare a:

- perdite finanziarie per la vittima
- disclosure del numero di cellulare della vittima se i messaggi sono inviati a indirizzi predefiniti che collezionano numeri di telefono

Una volta che l'URL schema è stato definito, più app possono registrarsi per gli schema disponibili.
Per ogni app, ognuna di queste URL schema custom deve essere enumerata e le action che eseguono devono essere testate.

Le URL schema possono essere usate per deep linking, un modo molto diffuso e conveniente per lanciare un'app nativa tramite link, che non è implicitamente rischioso.
Alternativamente, dall'API level 23 possono essere usati gli app link.
Gli app link, in contrasto con i deep link, necessitano di un dominio in cui il link venga servito in modo da avere un digital asset link.
Prima viene chiesto all'app di verificare l'asset link tramite `android:autoVerify="true"` nell'intentfiler.

Tuttavia, i dati elaborati dall'app e che provengono dagli URL schema dovrebbero essere validati come qualsiasi content:

- quando si usa un tipo persistente reflection-based per l'elaborazione dei dati, verifica la sezione "Testing Object Persistence" per Android
- vengono usati i dati per le query? assicurati che siano query parametrizzate
- vengono usati dati per azioni autenticate? assicurati che l'utente sia autenticato prima che i dati vengano elaborati
- se i dati alterati influenzano il risultato del calcolo: aggiungi un HMAC sui dati

### Static Analysis

221
