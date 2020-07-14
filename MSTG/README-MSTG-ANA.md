# Android Network APIs

## Testing Endpoint Identify Verification (MSTG-NETWORK-3)

Bisogna concentrarsi su due punti chiave:

- verificare che un certificato proviene da una trusted source (es. trusted CA)
- determinare se l'endpoint server ha il certificato corretto

Assicurati che l'hostname e lo stesso certificato siano verificati correttamente.
Cerca nel codice sorgente `TrustManager` e `HostnameVerifier`.

### Static Analysis

#### Verifying the Server Certificate

Il `TrustManager` permette di verificare le condizioni necessarie per poter stabilire una connessione sicura.
Bisogna controllare che:

- il certificato sia stato firmato da una CA fidata
- il certificato non sia scaduto
- il certificato non sia self-signed

#### WebView Server Certificate Verification

Alcune app usano WebView per renderizzare il sito associato con l'app.
Questo è valido per i framework basati su HTML/JavaScript come Apache Cordova, che usa una WebView interna per le interazioni con l'app.
Quando si usa una WebView, il browser mobile esegue una verifica del certificato del server.
Ignorare qualsiasi errore TLS che si verifica durante la connessione al sito remoto è una bad practice.

#### Apache Cordova Certificate Verification

L'implementazione di WebView interna al framework Apache Cordova ignora gli errori TLS nel metodo `onReceivedSslError` se il flag `android:debuggable` è abilitato nel manifest dell'app.
Assicurati quindi che l'app non sia degbugguable.

#### Hostname Verification

Un'altra vulnerabilità sull'implementazione di TLS lato client è la mancanza di hostname verification.
Gli ambienti di sviluppo di solito usano indirizzi interni invece di domain name validi, allora gli svilupptori disabilitano l'hostname verification (o forzano l'app a fidarsi di qualsiasi hostname) e si dimenticano di cambiarlo quando l'app va in produzione.

Assicurati che l'app verifichi l'hostname prima di instaurare una connessione sicura.

### Dynamic Analysis

Per l'analsi dinamica è necessario un interception proxy.
Per verificare l'implementazione, esegui i seguenti controlli:

- self-signed certificate:
in BURP, naviga in `Proxy` -> `Options` -> `Proxy Listeners`, seleziona il tuo listener, e clicca su `Edit`.
Nel tab `Certificate`, spunta `Use a self-signed certificate` e clicca su `Ok`.
Avvia l'app.
Se sei in grado di vedere il traffico HTTPS, allora l'app accetta il certificato self-signed.
- accepting invalid certificates:
in BURP, naviga in `Proxy` -> `Options` -> `Proxy Listeners`, seleziona il tuo listener, e clicca su `Edit`.
Nel tab `Certificate`, spunta `Generate a CA-Signed certificate with a specific hostname` e digita l'hostname del server di backend.
Avvia l'app.
Se sei in grado di vedere il traffico HTTPS, allora l'app accetta tutti i certificati.
- accepting incorrect hostnames:
in BURP, naviga in `Proxy` -> `Options` -> `Proxy Listeners`, seleziona il tuo listener, e clicca su `Edit`.
Nel tab `Certificate`, spunta `Generate a CA-Signed certificate with a specific hostname` e digita un hostname non valido (es. example.com).
Avvia l'app.
Se sei in grado di vedere il traffico HTTPS, allora l'app accetta tutti i certificati.

## Testing Custom Certificate Stores and Certificate Pinning (MSTG-NETWORK-4)

Con il certificate pinning si associa al server di backend un particolare certificato X.509 o una chiave pubblica invece di accettare qualsiasi certificato firmato da una CA fidata.
Dopo aver memorizzato ("pin") il certificato o la chiave pubblica del server, l'app si conetterà solo al server conosciuto.
Rimuovendo la fiducia da CA esterne riduce la superficie d'attacco.

Il certificato può essere pinned e hardcoded nell'app o recuperato quando l'app si connette per la prima volta al backend.
Nel secondo caso, il certificato è associato all'host quando l'host viene visto per la prima volta.
Questa alternativa è meno sicura perchè gli attaccanti che intercettano la connessione iniziale possono iniettare i propri certificati.

### Static Analysis

#### Network Security Configuration

La Network Security Configuration può essere usata per fare il pinning di certificati in modo dichiarativo su specifici domini.
Se l'app usa questa feature, bisogna eseguire i seguenti controlli.

Trova il file di Network Security Configuration nell'`AndroidManifest.xml` tramite l'attributo `android:networkSecurityConfig`.
Di solito il file è `res/xml/network_security_config.xml`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
	<domain-config>
		<!-- Use certificate pinning for OWASP website access including sub domains -->
		<domain includeSubdomains="true">owasp.org</domain>
		<pin-set expiration="2018/8/10">
			<!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
			the Intermediate CA of the OWASP website server certificate -->
			<pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
			<!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
			the Root CA of the OWASP website server certificate -->
			<pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
		</pin-set>
	</domain-config>
</network-security-config>
```

Se la configurazione è presente, potrebbe comparire il seguente log:

```
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

Se il controllo di certificate pinning fallisce, comparirà il seguente evento nel log:

```
I/X509Util: Failed to validate the certificate chain, error: Pin verification failed
```

Usando un decompiler (es. jadx o apktool) puoi verificare se l'entry `<pin>` è presente nel file network_security_config.xml presente nel folder /res/xml/.

#### TrustManager

L'implementazione del certificate pinning coinvolge tre step:

- ottenere il certificato degli host desiderati
- assicurarsi che il certificato sia nel formato .bks
- memorizzare il certificato nell'istanza di Apache Httpclient di default

L'HTTP client dovrebbe caricare il KeyStore:

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

Una volta che il KeyStore è stato caricato, possiamo usare il TrustManager che si fida delle CA nel nostro KeyStore:

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
// Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

L'implementazione dell'app potrebbe essere diversa, potrebbe fare il pinning rispetto alla sola chiave pubblica, all'intero certificato o a tutta la certificate chain.

#### Network Libraries and WebViews

Le app che usano network libraries di terze parti potrebbero usare le funzionalità di certificate pinning integrate nelle librerie stesse.
Per esempio, okhttp può essere configurato come segue:

```java
OkHttpClient client = new OkHttpClient.Builder()
	.certificatePinner(new CertificatePinner.Builder()
		.add("example.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
		.build())
	.build();
```

Le app che usano un componente WebView potrebbero usare l'event handler di WebViewClient per una specie di certificate pinning per ogni richiesta prima che la risorsa venga caricata.

```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
	private String expectedIssuerDN = "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US;";
		@Override
		public void onLoadResource(WebView view, String url) {
			//From Android API documentation about "WebView.getCertificate()":
			//Gets the SSL certificate for the main top-level page
			//or null if there is no certificate (the site is not secure).
			//
			//Available information on SslCertificate class are "Issuer DN", "Subject DN" and validity date helpers
			SslCertificate serverCert = view.getCertificate();
			if(serverCert != null){
				//apply either certificate or public key pinning comparison here
				//Throw exception to cancel resource loading...
			}
		}
	}
});
```

In alternativa, è meglio usare un OkHttpClient con i pin configurati e farlo agire come un proxy che fa l'overriding del metodo `shouldInterceptRequest` di `WebViewClient`.

#### Xamarin Applications

Le app sviluppate in Xamarin di solito usano ServicePointManager per implementare il certificate pinning.
Di norma si crea una funzione per controllare i certificati e restituire un valore booleano al metodo ServerCertificateValidationCallback:

```java
[Activity(Label = "XamarinPinning", MainLauncher = true)]
public class MainActivity : Activity
{
	// SupportedPublicKey - Hexadecimal value of the public key.
	// Use GetPublicKeyString() method to determine the public key of the certificate we want to pin. Uncom
	ment the debug code in the ValidateServerCertificate function a first time to determine the value to pin.
	private const string SupportedPublicKey = "3082010A02820101009CD30CF05AE52E47B7725D3783B3686330EAD73526
	1925E1BDBE35F170922FB7B84B4105ABA99E350858ECB12AC468870BA3E375E4E6F3A76271BA7981601FD7919A9FF3D0786771C8690E959
	1CFFEE699E9603C48CC7ECA4D7712249D471B5AEBB9EC1E37001C9CAC7BA705EACE4AEBBD41E53698B9CBFD6D3C9668DF232A42900C8674
	67C87FA59AB8526114133F65E98287CBDBFA0E56F68689F3853F9786AFB0DC1AEF6B0D95167DC42BA065B299043675806BAC4AF31B90497
	82FA2964F2A20252904C674C0D031CD8F31389516BAA833B843F1B11FC3307FA27931133D2D36F8E3FCF2336AB93931C5AFC48D0D1D6416
	33AAFA8429B6D40BC0D87DC3930203010001";
	private static bool ValidateServerCertificate(
		object sender,
		X509Certificate certificate,
		X509Chain chain,
		SslPolicyErrors sslPolicyErrors
	)
	{
		//Log.Debug("Xamarin Pinning",chain.ChainElements[X].Certificate.GetPublicKeyString());
		//return true;
		return SupportedPublicKey == chain.ChainElements[1].Certificate.GetPublicKeyString();
	}
	protected override void OnCreate(Bundle savedInstanceState)
	{
		System.Net.ServicePointManager.ServerCertificateValidationCallback += ValidateServerCertificate;
		base.OnCreate(savedInstanceState);
		SetContentView(Resource.Layout.Main);
		TesteAsync("https://security.claudio.pt");
	}
}
```

In questo modo si fa il pinning dell'intermediate CA della certification chain.
L'output dell'HTTP response sarà disponibile nei log di sistema.
Dopo aver decompresso il file APK, usare un decompiler .NET come dotPeak, ILSpy o dnSpy per decompilare le dll dell'app memorizzate nella cartella `Assemblies` e confermare l'uso del ServicePointManager.

#### Cordova Applications

Le app ibride basate su Cordova non supportano il certificate pinning nativamente, per questo vengono usati dei plugin.
Il più comune è PhoneGap SSL Certificate Checker.
Il metodo `check` viene usato per confermare la fingerprint e le callback determineranno il flusso esecutivo.

```java
// Endpoint to verify against certificate pinning.
var server = "https://www.owasp.org";
// SHA256 Fingerprint (Can be obtained via "openssl s_client -connect hostname:443 | openssl x509 -noout -fingerprint -sha256"
var fingerprint = "D8 EF 3C DF 7E F6 44 BA 04 EC D5 97 14 BB 00 4A 7A F5 26 63 53 87 4E 76 67 77 F0 F4 CC ED 67 B9";

window.plugins.sslCertificateChecker.check(
	successCallback,
	errorCallback,
	server,
	fingerprint);

function successCallback(message) {
	alert(message);
	// Message is always: CONNECTION_SECURE.
	// Now do something with the trusted server.
}

function errorCallback(message) {
	alert(message);
	if (message === "CONNECTION_NOT_SECURE") {
		// There is likely a man in the middle attack going on, be careful!
	} else if (message.indexOf("CONNECTION_FAILED") >- 1) {
		// There was no connection (yet). Internet may be down. Try again (a few times) after a little timeout.
	}
}
```

Dopo aver decompresso il file APK, i file Cordova/Phonegap saranno in `/assets/www`.
La cartella `plugins` contiene i plugin usati.
Devi cercare questi metodi nel codice JavaScript dell'app per confermarne l'utilizzo.

### Dynamic Analysis

L'analisi dinamica può essere eseguita lanciando un attacco MITM con il tuo interception proxy preferito.
Ti consentirà di monitorare il traffico tra il client (l'app) e il server di backend.
Se il proxy non è in grado di intercettare le HTTP request e response, allora il certificate pinning è stato implementato correttamente.

#### Bypassing Certificate Pinning

Esistono diversi modi per raggirare il certificate pinning in un black box test, in base al framework disponibile sul device:

- Objection: usa il comando `android sslpinning disable`
- Xposed: installa il modulo TrustMeAlready o SSLUnpinning
- Cydia Substrate: installa il package Android-SSL-TrustKiller

Per la maggior parte delle app, il certificate pinning può essere raggirato in pochi secondi, ma solo se l'app usa le API sfruttate da questi tool.
Se l'app implementa il certificate pinning con un framework o una libreria custom, questo deve essere patched e disattivato manualmente, il che potrebbe richiedere più tempo del normale.

#### Bypass Custom Certificate Pinning Statically

Nell'app, sia l'endpoint che il certificato (o il suo hash) devono essere definiti.
Dopo aver decompilato l'app, puoi cercare:

- hash dei certificati:
`grep -ri "sha256\|sha1" ./smali`.
Sostituisci gli hash individuati con l'hash della CA del tuo proxy.
Diversamente, se l'hash è accoppiato a un domain name, puoi provare a modificare il domain name con un domain non esistente in modo che il dominio originale non venga pinned.
Questo funziona sulle implementazioni OkHTTP offuscate
- file di certificati: 
`find ./assets -type f \( -iname \*.cer -o -iname \*.crt \)`.
Sostituisci questi file con il certificato del tuo proxy, assicurandoti che siano nel formato corretto.

Se l'app usa librerie native per implementare le comunicazioni di rete, è necessario eseguire un'ulteriore attività di reverse engineering.

Dopo aver eseguito queste operazioni, reimpacchetta l'app usando apktool e installala sul device.

#### Bypass Custom Certificate Pinning Dynamically

Il bypassing dinamico della logica di pinning è il metodo più conveniente dato che non è necessario raggirare alcun controllo di integrità e i tentativi di trial & errror sono più veloci.
La parte più difficile è l'individuazione del metodo corretto su cui fare hooking e può richiedere del tempo in base al livello di obfuscation.
Dato che gli sviluppatori di solito riusano le librerie esistenti, è utile cercare stringhe e file di licenza che identificano la libreria usata.
Una volta indiviudata la libreria usata, esamina il codice sorgente non obfuscated per trovare i metodi sui quali si può fare dynamic instrumentation.

Ad esempio, cosideriamo un'app che usa una libreria OkHTTP3 obfuscated.
Dalla documentazine possiamo capire che la classe CertificatePinner.Builder è responsabile dell'aggiunta dei pin per specifici domini.
Se puoi modificare gli argomenti al metodo Builder.add, puoi cambiare gli hash aggiungendo quelli corrispondenti al tuo certificato.
Puoi trovare il metodo corretto in due modi:

- cerca gli hash e i domain name come spiegato prima.
L'effettivo metodo di pinning viene di solito usato o definito in prossimità di queste stringhe
- cerca la signature del metodo nel codice smali

Per il meotod Builder.add, puoi trovare i possibili metodi invocando il comando: `grep -ri java/lang/String:\[Ljava/lang/String;)L ./`.
Questo comando cercherà tutti i metodi che prendono una stringa e una lista di stringhe come argomenti, e restituisce un complex object.
In base alle dimensioni dell'app, potrebbero esserci più match.
Fai l'hooking di ogni metodo con Frida e stampa gli argomenti.
Uno di essi stamperà il domain name e l'hash del certificato, dopo di che puoi modificare gli argomenti e raggirare l'impememntazione del certificate pinning.

## Testing the Network Security Configuration settings (MSTG-NETWORK-4)

### Trust Anchors

Su Android 7.0 o superiore, le app usano una Network Security Configuratin di default che non si fida delle CA aggiunte dall'utente, riducendo i possibili MITM dopo aver spinto l'utente a installare una CA malicious.
Questa protezione può essere raggirata usando una Network Security Configuration custom con un trust anchor custom che indica che l'app si fida delle CA aggiunte dall'utente.

### Static Analysis

Usa un decompiler (es. jadx o apktool) per confermare la versione dell'SDK target.
Dopo aver decodificato l'app puoi cercare `targetSDK` nel file apktool.yml che è stato creato nell'output folder.

La Network Security Configuration dovrebbe essere analizzata per determinare quali impostazioni sono configurate.

Se ci sono `<trust-anchors>` custom in un `<base-config>` o `<domain-config>`, che definiscono un `<certificates src="user">`, allora l'app si fiderà delle CA inserite dall'utente per quei particolari domini o per tutti i domini.

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
	<base-config>
		<trust-anchors>
			<certificates src="system"/>
			<certificates src="user"/>
		</trust-anchors>
	</base-config>
	<domain-config>
		<domain includeSubdomains="false">owasp.org</domain>
		<trust-anchors>
			<certificates src="system"/>
			<certificates src="user"/>
		</trust-anchors>
		<pin-set expiration="2018/8/10">
			<!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
			the Intermediate CA of the OWASP website server certificate -->
			<pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
			<!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
			the Root CA of the OWASP website server certificate -->
			<pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
		</pin-set>
	</domain-config>
</network-security-config>
```

Se un valore non è impostato in un'entry `<domain-config\>` o in un nodo padre `<domain-config\>`, le configurazioni saranno basate su `<base-config\>`, diversamente se non definite in questa entry, verrà applicata la configurazione di default.
La configurazione di default delle app per Android 9 o superiore è:

```xml
<base-config cleartextTrafficPermitted="false">
	<trust-anchors>
		<certificates src="system" />
	</trust-anchors>
</base-config>
```

Per Android 7.0 e 8.1.

```xml
<base-config cleartextTrafficPermitted="true">
	<trust-anchors>
		<certificates src="system" />
	</trust-anchors>
</base-config>
```

Per Android 6.0 e inferiori:

```xml
<base-config cleartextTrafficPermitted="true">
	<trust-anchors>
		<certificates src="system" />
		<certificates src="user" />
	</trust-anchors>
</base-config>
```

### Dynamic Analysis

Puoi testare le impostazioni di Network Security Configuration usando un approccio dinamico, tipicamente con un interception proxy come Burp.
Tuttavia, potrebbe essere possibile che tu non sia in grado di vedere il traffico, es. per app su Android 7.0 o superiori che applicano la Network Security Configuration.
In questa situazione, dovresti applicare una patch al file di Network Security Configuration.

Potrebbero esserci degli scenari in cui non è necessario e in cui puoi fare attacchi di MITM senza patching:

- quando l'app è in esecuzione su un device con Android 7.0 o successivi, ma l'app è stata compilata per API level inferiori a 24, non userà il file di Network Security Configuration.
Si fiderà invece di qualsiasi CA caricata dall'utente
- quando l'app è in esecuzione su un device con Android 7.0 o successivi e non è presente una Network Security Configuration custom implementata nell'app

## Testing the Security Provider (MSTG-NETWORK-6)

Android si appoggia su un security provider per gestire le connessioni SSL/TLS.
Il problema con questo tipo di security provider (es. OpenSSL), che è già installato sul device, è che spesso ha bug e vulnerabilità.
Per evitare vulnerabilità conosciute, gli sviluppatori devono assicurarsi che l'app usi un security provider adeguato.

### Static Analysis

Le app basate sull'Android SDK dovrebbero dipendere dai GooglePlayServices.
Per esempio, nel build file di gradle, troverai `compile 'com.google.android.gms:play-services-gcm:x.x.x'` nel blocco delle dipendenze.
Devi assicurarti che la classe `ProviderInstaller` venga invocata con `installIfNeeded` o `installIfNeededAsync`.
Il `ProviderInstaller` deve essere invocato da un componente dell'app il prima possibile.
Le eccezioni lanciate da questi metodi dovrebbero essere catched e gestite correttamente.
Se l'app non può applicare la patch al suo security provider, può informare le API del suo stato meno sicuro oppure restringere le azioni dell'utente (dato che il traffico HTTPS dovrebbe essere considerato più rischioso in questa situazione).

Lo sviluppatore deve gestire le eccezioni adeguatamente, e segnalare al backend quando l'app è in esecuzione con un security provider non patched.

Assicurati che le app basate su NDK si appoggino solo su una libreria che fornisce funzionalità SSL/TLS recente e adeguatamente patched.

### Dynamic Analysis

Se hai il codice sorgente:

- esegui l'app in debug mode, poi crea un breakpoint nel punto in cui l'app contatta gli endpoint per la prima volta
- evidenzia il codice e dopo click destro scegli `Evaluate Expression`
- digita `Security.getProviders()` e premi Invio
- controlla i provider e cerca `GmsCore_OpenSSL`, che dovrebbe essere il primo della lista

Se non hai il codice sorgente:

- usa Xposed per fare l'hooking nel package `java.security`, poi fai l'hooking in `java.security.Security` sul metodo `getProviders` (senza argomenti).
Il valore ritornato sarà un array di `Provider`
- verifica se il primo provider è `GmsCore_OpenSSL`
