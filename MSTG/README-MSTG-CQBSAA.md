# Code Quality and Build Settings of Android Apps

## Making Sure That the App is Properly Signed (MSTG-CODE-1)

Android richiede che tutte le APK siano firmate digitalmente con un certificato prima di essere installate o eseguite.
La firma digitale viene usata per verificare l'identità del possessore degli aggiornamenti dell'app.
Questo processo impedisce che l'app venga modificata con codice malevolo.

Quando l'APK viene firmata, le viene allegato un certificato a chiave pubblica.
Questo certificato associa univocamente l'APK allo sviluppatore e alla chiave privata dello stesso.
Quando un'app è stata compilata in debug mode, l'Android SDK firma l'app con una chiave di debug creata specificamente per scopi di debug.
Un'app firmata con una chiave di debug non è pensata per essere rilasciata e non verrà accettata nella maggior parte degli app store, incluso il Google Play Store.

La build finale di release di un'app dovrà essere firmata con una chiave di release valida.
In Android Studio, l'app può essere firmata manualmente o tramite la creazione di una signing configuration che è assegnata al tipo release della build.

Prima di Android 9 tutti gli aggiornamenti su Android devono essere firmati con la stessa chiave, quindi è raccomandato un periodo di validità di 25 anni.
Le app pubblicate su Google Play devono essere firmate con una chiave che ha un periodo di validità che finisce dopo il 22 ottobre 2033.

Sono disponibili tre scheme di firma di APK:

- JAR signing (v1 scheme)
- APK Signature Scheme v2 (v2 scheme)
- APK Signature Scheme v3 (v3 scheme)

La v2 signature, che è supportata da Android 7.0 e superiori, offre sicurezza e performance migliorate rispetto alla v1 scheme.
La v3 signature, che è supportata da Android 9 e superiori, dà la possibilità alle app di cambiare le chiavi di firma durante un aggiornamento dell'APK.
Questa funzionalità assicura la compatibilità e la continua disponibilità delle app consentendo l'uso sia delle vecchie che delle nuove chiavi.

Per ogni scheme di firma le release dovrebbero essere sempre firmate con tutti gli scheme precedenti.

### Static Analysis

Assicurati che la release sia stata firmata sia tramite lo scheme v1 che v2 per Android 7.0 e superiori e tramite tutti e tre gli scheme per Android 9 e superiori, e che il certificato di firma del codice nell'APK appartenga allo sviluppatore.

Le firme dell'APK possono essere firmate con il tool `apksigner`.
Si trova in `[SDK-Path]/build-tools/[version]`.

```sh
$ apksigner verify --verbose Desktop/example.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
```

Il contenuto del certificato di firma può essere esaminato con `jarsigner`.
Nota che l'attributo Common Name (CN) viene impostato ad "Android Debug" nei certificati di debug.

L'output per un'APK firmata con un certificato di debug viene mostrato di seguito:

```sh
jarsigner -verify -verbose -certs example.apk
sm 	11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

	X.509, CN=Android Debug, O=Android, C=US
	[certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
	[CertPath not validated: Path doesn\'t chain with any of the trust anchors]
(...)
```

Ignora l'errore "CertPath not validated".
Questo errore si verifica con Java SDK 7 e superiori.
Invece di usare `jarsigner` puoi usare `apksigner` per verificare la catena di certificati.

La signing configuration può essere gestita tramite Android Studio o il blocco `signingConfig` in `build.gradle`.
Per attivare tutti e tre gli scheme, i seguenti valori devono essere impostati:

```sh
v1SigningEnabled true
v2SigningEnabled true
v3SigningEnabled true
```

Molte best practice per la configurazione dell'app per la release sono disponibili nella documentazione ufficiale di Android developer.

### Dynamic Analysis

Bisogna applicare l'analisi statica per verificare la firma delle APK.

## Testing Whether the App is Debuggable (MSTG-CODE-2)

L'attributo `android:debuggable` nell'elemento `Application` che è definito nell'AndroidManifest.xml determina se l'app può essere debugged o meno.

### Static Analysis

Ispeziona l'AndroidManifest.xml per verificare se l'attributo `android:debuggable` è stato impostato e quale valore gli è stato assegnato.

```xml
...
<application android:allowBackup="true" android:debuggable="true" 
	android:icon="@drawable/ic_launcher" android:label="@string/app_name" 
	android:theme="@style/AppTheme">
...
```

Per una build di release, questo attributo dovrebbe essere sempre impostato a `false` (valore di default).

### Dynamic Analysis

Puoi usare Drozer per verificare se l'app è debuggable.
Il modulo Drozer `app.package.attacksurface` mostra anche informazioni su componenti di IPC esportati dall'app.

```sh
dz> run app.package.attacksurface com.mwr.dz
Attack Surface:
	1 activities exported
	1 broadcast receivers exported
	0 content providers exported
	0 services exported
	is debuggable
```

Per individuare tutte le app debuggable sul device, usa il modulo `app.package.debuggable`:

```sh
dz> run app.package.debuggable
Package: com.mwr.dz
	UID: 10083
	Permissions:
		- android.permission.INTERNET
Package: com.vulnerable.app
	UID: 10084
	Permissions:
		- android.permission.INTERNET
```

Se un'app è debuggable, l'esecuzione di comandi dell'app è banale.
Nella shell `adb`, esegui `run-as` concatenando il package name e il comando dell'app

```sh
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

Android Studio può essere usato per fare il debugging di un'app e verificare l'attivazione del debugging.

Un altro metodo per verificare se un'app è debuggable è agganciare `jdb` al processo in esecuzione.
Se ciò è possibile, allora il debugging è attivo.

La seguente procedura può essere usata per avviare una sessione di debugging con `jdb`:

1. usando `adb` e `jdwp`, identifica il PID dell'app di cui vuoi fare il debug

```sh
$ adb jdwp
2355
16346 <== last launched, corresponds to our application
```

2. crea un canale di comunicazione usando `adb` tra il processo dell'app e la tua macchina usando una specifica porta locale:

```sh
# adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PID]
$ adb forward tcp:55555 jdwp:16346
```

3. usando `jdb`, aggancia il debugger alla porta e avvia la sessione di debug:

```sh
$ jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> help
```

Alcune note sul debugging:

- il tool `JADX` può essere usato per identificare posizioni interessanti per inserire breakpoint
- se si verifica l'errore "the connection to the debugger has been closed" mentre `jdb` è connesso alla porta, termina le sessioni `adb` e riavviane una nuova.

## Testing for Debugging Symbols (MSTG-CODE-3)

Di solito, dovresti fornire codice compilato con meno informazioni/spiegazioni possibili.
Alcuni metadati, come informazioni di debugging, line number, e nomi di funzioni e metodi descrittivi, rendono il binario o il byte-code più facile da analizzare durante il reverse engineering, 
ma queste informazioni non sono necessarie in una build di release e possono quindi essere omesse senza impattare sulle funzionalità dell'app.

Per ispezionare i binari nativi, usa i tool standard come `nm` o `objdump` per esaminare la tabella dei simboli.
Una build di release non dovrebbe di solito contenere informazioni di debug.
Se l'obiettivo è offuscare la libreria, si raccomanda di rimuovere anche le informazioni dinamiche non necessarie.

### Static Analysis

I simboli sono in realtà rimossi durante il processo di compilazione, quindi devi assicurarti che dal byte-code e dalle librerie i metadati non necessari siano stati rimossi.

Prima, trova il file binario `nm` nell'Android NDK ed esportalo:

```sh
export $NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-android eabi-nm
```

Per mostrare i simboli di debug

```sh
$ $NM -a libfoo.so
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```

Per mostrare i simboli dinamici

```sh
$ $NM -D libfoo.so
```

Alternativamente, apri il file in un disassembler a tua scelta e controlla la tabella dei simboli manualmente.

I simboli dinamici possono essere rimossi tramite il flag `visibility` del compiler.
Aggiungendo questo flag, gcc scarterà i nomi di funzioni mentre manterrà i nomi di funzioni dichiarate `JNIEXPORT`.

Assicurati che la seguente configurazione sia stata aggiunta a build.gradle:

```sh
externalNativeBuild {
	cmake {
		cppFlags "-fvisibility=hidden"
	}
}
```

### Dynamic Analysis

L'analisi statica dovrebbe essere usata per verificare i simboli di debug.

## Testing for Debugging Code and Verbose Error Logging (MSTG-CODE-4)

StrictMode è un tool per l'identificazione di violazioni, 
es. accessi a disco o rete accidentali nel thread principale dell'app.
Può anche essere usato per good cooding practice, come l'implementazione di codice performante.
Segue un esempio di `StrictMode` con le policy per accesso a disco e rete abilitate per il thread principale:

```java
public void onCreate() {
	if (DEVELOPER_MODE) {
		StrictMode.setThreadPolicy(
			new StrictMode.ThreadPolicy.Builder()
				.detectDiskReads()
				.detectDiskWrites()
				.detectNetwork() // or .detectAll() for all detectable problems
				.penaltyLog()
				.build());

		StrictMode.setVmPolicy(
			new StrictMode.VmPolicy.Builder()
				.detectLeakedSqlLiteObjects()
				.detectLeakedClosableObjects()
				.penaltyLog()
				.penaltyDeath()
				.build());
	}

	super.onCreate();
}
```

Si raccomanda di inserire la policy nel blocco `if` con la condizione `DEVELOPER_MODE`.
Per disabilitare `StrictMode`, bisogna disabilitare `DEVELOPER_MODE` per la build di release.

### Static Analysis

Per verificare se `StrictMode` è abilitato, puoi cercare i metodi `StrictMode.setThreadPolicy` o `StrictMode.setVmPolicy`.
Di solito, si trovano nel metodo `onCreate`.

I metodi di individuazione per la policy del thread sono:

```java
detectDiskWrites()
detectDiskReads()
detectNetwork()
```

Le penalty per la violazione della policy del thread sono:

```java
penaltyLog()
penaltyDeath()
penaltyDialog()
```

### Dynamic Analysis

Ci sono diversi modi per individuare `StrictMode`;
il modo migliore dipende in base a come i ruoli delle policy sono implementate.
Questi includono:

- logcat
- dialog di warning
- crash dell'app

## Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5)

Le app Android spesso usano librerie di terze parti.
Queste librerie accelerano lo sviluppo dato che lo sviluppatore deve scrivere meno codice per risolvere un problema.
Ci sono due categorie di librerie:

- librerie che non sono (o non dovrebbero essere) incluse nell'app di produzione finale, 
come `Mockito` usato per il testing 
e librerie come `JavaAssist` usato per compilare altre librerie
- librerie che sono incluse nell'app di produzione finale, come `Okhttp3`

Queste librerie potrebbero avere le seguenti due classi di effetti collaterali non voluti:

- una libreria può contenere una vulnerabilità, che renderebbe l'applicazione vulnerabile.
Un buon esempio sono le versioni di `OKHTTP` prima di 2.7.5 in cui era possibile la TLS chain pollution per il bypass dell'SSL pinning
- una libreria può usare una licenza, come LGPL2.1, che richiede all'autore dell'app di dare accesso al codice sorgente a coloro che usano l'app.
Risulta poi possibile redistribuire l'app con modifiche al suo codice sorgente.
Ciò può ledere alla proprietà intellettuale dell'app

Nota che questo problema potrebbe intaccare a diversi livelli:
quando usi le webview con JavaScript in esse, le librerie JavaScript potrebbero avere questo tipo di licenza.
Lo stesso vale per plugin/librerie di Cordova, app React-native e app Xamarin.

### Static Analysis

#### Detecting vulnerabilities of third party libraries

L'individuazione delle vulnerabilità nelle dipendenze può essere eseguita tramite l'OWASP Dependency checker.
Si consiglia l'uso di un plugin gradle, come `dependecy-check-gradle`.
Per usare il plugin, segui i seguenti passi:
installa il plugin dal Maven central repository aggiungendo il seguente script in build.gradle:

```sh
buildscript {
	repositories {
		mavenCentral()
	}

	dependencies {
		classpath 'org.owasp:dependency-check-gradle:3.2.0'
	}
}

apply plugin: 'org.owasp.dependencycheck'
```

Una volta che gradle ha invocato il plugin, puoi creare un report lanciando:

```sh
$ gradle assemble
$ gradle dependencyCheckAnalyze --info
```

Il report verrà creato in `build/reports` a meno di diversa configurazione.
Usa il report per analizzare le vulnerabilità trovate.
Date le vulnerabilità trovate nelle librerie, cerca le remediation.
L'utilizzo del plugin richiede il download di un vulnerability feed.

Diversamente, ci sono tool commerciali che potrebbero avere una migliore copertura sulle dipendenze trovate nelle librerie usate, come SourceClear o Blackduck.
Il risultato reale nell'uso dell'OWASP Dependency Checker o di un altro tool cambia a seconda del tipo di libreria.

Infine, nota che per app ibride, è necessario verificare le dipendenze JavaScript con RetireJS.
Analogamente, per Xamarin, è necessario verificare le dipendenze di C#.

- la libreria è inclusa nell'app?
Controlla se la libreria ha una versione in cui la vulnerabilità è patched. 
Se non lo è, verifica se la vulnerabilità impatta sull'app.
Se è il caso o potrebbe succedere nel futuro, cerca un'alternativa che fornisca funzionalità simili, ma senza vulnerabilità
- la libreria non è inclusa nell'app? 
Controlla se esiste una versione in cui la vulnerabilità è stata patched.
Se non lo è, controlla se la vulnerabilità impatta l'app.
La vulnerabilità può bloccare la compilazione o indebbolire la sicurezza della build-pipeline?
Poi cerca un'alternativa in cui la vulnerabilità viene patched

Quando i sorgenti non sono disponibili, puoi decompilare l'app e verificare i file jar.
Quando Dexguard o Proguard sono applicati adeguatamente, le informazioni sulla versione della libreria sono spesso offuscate.
Altrimenti, puoi trovare informazioni nei commenti dei file Java della libreria stessa.
Se puoi risalire alla versione della libreria, tramite i commenti o tramite specifici metodi usati in certe versioni, puoi ricercare manulamente i relativi CVE.

#### Detecting the licenses used by the libraries of the application

Per assicurarti che il copyright non sia violato, puoi controllare le dipendenze usando un plugin che itera nelle diverse librerie, come `License Gradle Plugin`.
Questo plugin può essere usato seguendo i seguenti passi.

Nel tuo build.gradle aggiungi:

```sh
plugins {
	id "com.github.hierynomus.license-report" version"{license_plugin_version}"
}
```

Poi lancia:

```sh
$ gradle assemble
$ gradle downloadLicenses
```

Verrà generato un license-report, che può essere usato per consulatre le licenze usate dalle librerie di terze parti.
Controlla i license agreement per vedere se è necessario includere una copyright notice nell'app e se il tipo di licenza richiede la pubblicazione del codice sorgente dell'app.

Come per il controllo delle dipendenze, ci sono tool commerciali in grado di controllare anche le licenze, come SourceClear, Snyk o Blackduck.

> Nota: se hai dubbi sulle implicazioni di un modello di licenza usato da una libreria di terze parti, consulta uno specialista legale

Quando una libreria contiene una licenza in cui la proprietà intellettuale dell'app deve essere resa pubblica, 
verifica se esiste un'alternativa per la libreria che può essere usata per fornire funzionalità simili.

Nota: in caso di app ibrida, controlla il tool di build usato, molti hanno un plugin di enumerazione di licenze per trovare le licenze usate.

Quando non hai a disposizione il codice sorgente, puoi decompilare l'app e controllare i file jar.
Se Dexguard o Proguard sono applicati adeguatamente, le informazioni sulla versione delle librerie sono spesso rimosse.
Diversamente puoi trovare le versioni delle librerie nei commenti dei file Java delle librerie.
Tool come MobSF possono aiutare nell'analisi delle librerie incluse nell'app.
Se puoi recuperare la versione della libreria, anche tramite i commenti o tramite uno specifico metodo usato dalla versione, puoi cercare le loro licenze manualmente.

### Dynamic Analysis

L'analisi dinamica di questa sezione consiste nel controllare se si è aderito ai copyright delle licenze.
Spesso significa che l'app dovrebbe avere una sezione `about` o `EULA` in cui le dichiarazioni di cocpyright sono annotate come richiesto nelle licenze delle librerie di terze parti.

## Testing Exception Handling (MSTG-CODE-6 and MSTG-CODE-7)

Le eccezioni si verificano quando un'app giunge a uno stato anormale o di errore.
Sia Java che C++ possono lanciare eccezioni.
Il testing della gestione delle eccezioni consiste nell'assicurarsi che l'app le gestisca adeguatamente ed entri in uno stato stabile senza esporre informazioni sensibili tramite l'interfaccia utente o i meccanismi di logging.

### Static Analysis

Analizza il codice per comprendere il funzionamento dell'app e identifica in che modo gestisce i vari tipi di errore (comunicazioni IPC, invocazione di servizi remoti, ecc.).
Seguono alcuni controlli da effetturare:

- assicurati che l'app usi un sistema di gestione delle eccezioni ben progettato e unificato
- prepara il codice alle `RuntimeException` standard (es. `NullPointerException`, `IndexOutOfBoundsException`,
`ActivityNotFoundException`, `CancellationException`, `SQLException`) imponendo i null check, bound check e simili.
Una panoramica delle sottoclassi di `RuntimeException` è disponibile nella documentazione di Android developer.
Una sottoclasse di `RuntimeException` dovrebbe essere lanciata intenzionalmente, e l'intent dovrebbe gestirla chiamando il relativo metodo
- assicurati che per ogni `Throwable` non-runtime ci sia un adeguato blocco catch, che gestisca adeguatamente l'eccezione
- quando viene lanciata un'eccezione, assicurati che l'app abbia degli handler centralizzati per le eccezioni.
Può anche essere una classe statica.
Per eccezioni specifiche del metodo, inserire un blocco catch specifico
- assicurati che l'app non esponga informazioni sensibili durante la gestione delle eccezioni nell'interfaccia utente o nei log.
Assicurati che le eccezioni siano sufficientemente verbose per spiegare il problema all'utente
- assicurati che tutte le informazioni confidenziali gestite dalle app ad alto rischio siano rimosse durante l'esecuzione del blocco `finally`

```java
byte[] secret;

try{
	//use secret
} catch (SPECIFICEXCEPTIONCLASS | SPECIFICEXCEPTIONCLASS2 e) {
	// handle any issues
} finally {
	//clean the secret.
}
```

L'aggiunta di un handler generale per eccezioni non catturate è una best practice.

```java
public class MemoryCleanerOnCrash implements Thread.UncaughtExceptionHandler {
	private static final MemoryCleanerOnCrash S_INSTANCE = new MemoryCleanerOnCrash();
	private final List<Thread.UncaughtExceptionHandler> mHandlers = new ArrayList<>();

	//initialize the handler and set it as the default exception handler
	public static void init() {
	S_INSTANCE.mHandlers.add(Thread.getDefaultUncaughtExceptionHandler());
		Thread.setDefaultUncaughtExceptionHandler(S_INSTANCE);
	}

	//make sure that you can still add exception handlers on top of it (required for ACRA for instance)
	public void subscribeCrashHandler(Thread.UncaughtExceptionHandler handler) {
		mHandlers.add(handler);
	}

	@Override
	public void uncaughtException(Thread thread, Throwable ex) {
		//handle the cleanup here
		//....
		//and then show a message to the user if possible given the context
		for (Thread.UncaughtExceptionHandler handler : mHandlers) {
			handler.uncaughtException(thread, ex);
		}
	}
}
```

L'initializer dell'handler deve essere invocato nella classe `Application`:

```java
@Override
protected void attachBaseContext(Context base) {
	super.attachBaseContext(base);
	MemoryCleanerOnCrash.init();
}
```

### Dynamic Analysis

Ci sono diversi modi di eseguire l'analisi dinamica.

- usa Xposed per fare l'hooking dei metodi e invocarli con valori inattesi o sovrascrivere variabili esistenti con valori inattesi (es. valori null)
- digita valori inaspettati nei campi dell'interfaccia utente dell'app
- interagisci con l'app usando i suoi intent, i suoi provider pubblici e usa valori inaspettati
- modifica le comunicazioni di rete e/o i file memorizzati nell'app

L'app non dovrebbe mai andare in crash; dovrebbe:

- ristabilizzarsi dopo l'errore o entrare in uno stato in cui può informare l'utente dell'impossibilità di continuare
- se necessario, comunica all'utente di prendere determinate decisioni (il messaggio non dovrebbe rivelare informazioni sensibili)
- non fornire alcuna informazione nei meccanismi di logging usati dall'app

## Memory Corruption Bugs (MSTG-CODE-8)

Le app Android di solito vengono eseguite in una VM in cui la maggior parte dei problemi di corruzione di memoria sono stati risolti.
Ciò non significa che non ci siano bug di corruzione di memoria.
Per esempio CVE-2018-9522 è relativa alla serializzazione tramite Parcel.
Nel codice nativo, è presente lo stesso problema come già spiegato nella sezione generale sulla corruzione della memoria.
Infine, ci potrebbero essere dei bug di memoria nei service.

Un memory leak è spesso anche un problema.
Può accadere per esempio quando un riferimento all'oggetto `Context` è passato a classi non-`Activity`o quando lo si passa da classi `Activity` alle proprie helperclass.

### Static Analysis

Ci sono diversi aspetti da valutare:

- c'è codice nativo?
In caso positivo, verifica se sono presenti i problemi visti nella sezione della corruzione di memoria.
Il codice nativo può essere facilmente individuato tramite i wrapper JNI, i file .CCP/.H/.C, NDK o altri framework nativi
- c'è codice Java o Kotlin?
Cerca problemi di serializzazione/deserializzazione

Nota che ci potrebbero essere problemi di memory leak anche in codice Java/Kotlin.
Cerca diversi elementi:
BroadcastReceiver che non sono registrati,
riferimenti statici ad `Activity` o a `View`,
classi singleton che hanno riferimenti a `Context`,
riferimenti a classi interne,
riferimenti a classi anonime,
riferimenti ad AsyncTask,
riferiementi ad handler,
threading errato,
riferimenti a TimerTask.

### Dynamic Analysis

Ci sono diversi passi da seguire:

- in caso di codice nativo: 
usa Valgrind o Mempatrol per analizzare l'uso della memoria e le chiamate eseguite dal codice
- in caso di codice Java/Kotlin: 
prova a ricompilare l'app usando il plugin leak canary di Square.
- individua i leakage con il Memory Profiler di Android Studio
- individua le vulnerabilità di serializzazione con l'Android Java Deserialization Vulnerability Tester

## Make Sure That Free Security Features Are Activated (MSTG-CODE-9)

Dato che il decompilare le classi Java è banale, 
si raccomanda l'applicazione di un offuscamento base al byte-code nella build di release.
ProGuard offre un modo facile per minificare e offuscare il codice e per rimuovere informazioni di debugging non necessarie da qualsiasi byte-code dell'app.
Sostituisce gli identifier, come nomi di classi, nomi di metodi, e nomi di variabili, con stringhe senza un significato.
Questo è un tipo di offuscamento, che è "gratis" nel senso che non impatta le performance dell'app.

Dato che molte app Android sono Java-based, sono immuni a vulnerabilità di buffer overflow.
Tuttavia, una vulnerabilità di buffer overflow potrebbe riguardare l'app se questa usa l'Android NDK;
Perciò considera l'applicazione di configurazioni sicure per il compiler.

### Static Analysis

Se disponi del codice sorgente, puoi controllare nel file build.gradle se le impostazioni di offuscamento sono state applicate.
Nell'esempio che segue, puoi vedere che `minifyEnabled` e `proguardFiles` sono abilitati.
É comune l'esclusione di alcune classi dall'offuscamento (con `-keepclassmembers` e `-keepclass`).
Perciò, è importante verificare il file di configurazione di ProGuard per capire quali classi sono escluse.
Il metodo `getDefaultProguardFile('proguard-android.txt')` recupera il file di configurazione di default dalla directory `<Android SDK>/tools/proguard`.
Nel file `proguard-rules.pro` puoi definire regole ProGuard custom.
Puoi notare che molte classi estese nel file `proguard-rules.pro` di esempio sono classi Android comuni.
Dovrebbe essere definito più nello specifico per le classi o per le librerie.

Di default, ProGuard rimuove gli attributi che sono utili per il debug, come line number, nomi di file sorgente, e nomi di variabili.
ProGuard è un tool Java free che fa da shrinker, optimizer, obfuscator e pre-verifier.
É incluso nei tool dell'Android SDK.
Per attivare lo shrinking per la build di release, aggiungi il seguente script a build.gradle:

```sh
android {
	buildTypes {
		release {
			minifyEnabled true

			proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
		}
	}
	...
}
```

E in proguard-rules.pro:

```sh
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
```

### Dynamic Analysis

Se non hai a disposizione il codice sorgente, puoi decompilare un'APK per verificare se il codice è stato offuscato.
Diversi tool sono disponibili per la conversione del codice dex in un jar file.
Il jar file può essere aperto con tool (come JD-GUI) che possono essere usati per assicurarsi che nomi di classi e di variabili non siano human-readable.

Segue un esempio di codice offuscato:

```java
package com.a.a.a;
import com.a.a.b.a;
import java.util.List;

class a$b extends a
{
	public a$b(List paramList)
	{
		super(paramList);
	}

	public boolean areAllItemsEnabled()
	{
		return true;
	}

	public boolean isEnabled(int paramInt)
	{
		return true;
	}
}
```
