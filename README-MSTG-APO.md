# Android Platform Overview

## Android security architecture

Le app Android sono di solito sviluppate in Java e compilate in bytecode Dalvik, che è in qualche modo diverso dal bytecode Java.
Il bytecode Dalvik è creato prima compilando il codice Java in file .class, poi convertendo il bytecode JVM nel formato Dalvik .dex con il tool `dx`.

La versione attuale di Android esegue questo bytecode nell'Android Runtime (ART).
L'ART è il successore del runtime originale di Android, la Dalvik Virtual Machine.
La differenza principale tra i due è il modo in cui eseguono il bytecode.

In Dalvik, il bytecode viene tradotto in codice macchina a tempo di esecuzione, con un processo conosciuto come compilazione just-in-time (JIT).
Questo processo impatta negativamente sulle performance: la compilazione deve essere fatta ogni volta che l'app viene eseguita.
Per migliorare le performance, l'ART ha introdotto la compilazione ahead-of-time (AOT).
In questo modo, le app sono precompilate prima che vengano eseguite per la prima volta.
Questo codice macchina precompilato viene usato per tutte le esecuzioni successive.
L'AOT raddoppia le prestazioni e riduce il consumo di batteria.

Le app Android non hanno accesso diretto alle risorse hardware, e ogni app viene eseguita in una sandbox.
Ciò permette di controllare le risorse e le app: per esempio un'app che va in crash non influenza le altre app in esecuzione sul device.
Al tempo stesso, il runtime di Android controlla il numero massimo di risorse allocate per le app, impedendo che una qualsiasi app ne monopolizzi troppe.

## Android Users and Groups

Il supporto multi-user del kernel Linux viene sfruttato per fare il sandboxing delle app: con alcune eccezioni, ogni app viene eseguita tramite un utente Linux separato, isolandola effettivamente dalle altre app e dal resto del sistema operativo.

## Android Device Encryption

Android supporta la cifratura del device a partire da Android 2.3.4 (API level 10).

Android 5.0 (API level 21) e successivi supportano la full-disk encryption.
Si usa una singola chiave protetta dalla password del device per cifrare e decifrare la partizione userdata.
Questo tipo di cifratura viene considerata deprecata e la file-based encryption dovrebbe essere usata quando possibile.
La full-disk encryption ha degli incovenienti, come l'impossibilità di ricevere chiamate o non avere sveglie attive dopo il reboot prima che l'utente abbia inserito la password.

Android 7.0 (API level 24) supporta la file-based encryption.
Questa permette di cifrare file diversi con chiavi diverse in modo che possano essere decifrati indipendentemente.
I device che supportano questo tipo di cifratura supporano anche il Direct Boot.
Il Direct Boot permette al device di avere accesso a feature come sveglia o accessibility service anche se l'utente non ha inserito la password.

## Linux UID/GID for Normal Applications

Android crea un UID unico per ogni app e la esegue in un processo separato.
Quindi ogni app può accedere solo alle sue risorse.
Questa protezione è imposta dal kernel Linux.

Di solito alle app viene assegnato un UID nell'intervallo 10000-99999.
Le app ricevono un user name basato sul loro UID.
Per esempio, un app con UID 10188 riceve un user name `u0_a188`.
Se i permessi richiesti all'app vengono concessi, il corrispondente group ID viene aggiunto al processo dell'app.
Per esempio, nel seguente output di `id` possiamo vedere che l'app con UID 10188 appartiene al group ID 3003.
Tale gruppo è relativo al permesso `android.permission.INTERNET`.

```
$ id
uid=10188(u0_a188) gid=10188(u0_a188) groups=10188(u0_a188),3003(inet),
9997(everybody),50188(all_a188) context=u:r:untrusted_app:s0:c512,c768
```

## The App Sandbox

Le app sono eseguite nell'Android Application Sendbox, che separa i dati dell'app e il codice di esecuzione dalle altre app sul device.
Ciò aggiunge un livello di sicurezza.

L'installazione di una nuova app crea una nuova directory denominata con il nome del suo package, secondo il path `/data/data/[package-name]`.
Questa directory contiene i dati dell'app.
I permessi della directory vengono impostati in modo che venga letta e scritta solo dall'UID dell'app.

Gli sviluppatori che vogliono che le loro app condividano una sandbox comune possono scavalcare il sandboxing, configurando adeguatamente AndroidManifest.xml e firmandole con lo stesso certificato.

Il processo `Zygote` viene avviato durante l'installazione Android.
Serve a lanciare le app e contiene tutte le librerie core di cui le app hanno bisogno.
Al momento del lancio, Zygote apre un socket su `/dev/socket/zygote` e si mette in attesa di connessioni dai client locali.
Quando riceve una connessione, fa il fork di un nuovo processo, che carica ed esegue il codice specifico dell'app.

In Android, il ciclo di vita di un processo di un app è controlato dal sistema operativo.
Viene creato un processo Linux quando un componente dell'app viene avviato e contemporaneamente l'app non ha ancora nessun altro componente in esecuzione.
Android potrebbe terminare questo processo quando l'ultimo non è più necessario o quando è richiesta della memoria per eseguire app più importanti.
La decisione di terminare un processo è fondamentalmente correlata allo stato dell'interazione dell'utente con il processo.
In generale i processi possono essere in uno di quattro stati:

- foreground:
es. un'activity in esecuzione sullo screen o un BroadcastReceiver in esecuzione
- visible:
processo di cui l'utente è a conoscenza, quindi la sua terminazione avrebbe un impatto negativo sulla user experience.
es. un'activity in esecuzione visibile sullo screen ma non nel foreground
- service:
processo che fornisce un servizio avviato con il metodo `startService`.
Anche se questi processi non sono direttamente visibili all'utente, di solito hanno l'attenzione dell'utente (es. uplodad o download di dati in background), quindi il sistema cercherà sempre di mantenere tali processi in esecuzione a meno che non ci sia sufficiente memoria per mantenere tutti i processi foreground e visible
- cached:
processo che non è attualmente necessario, allora il sistema può terminarlo quando è richiesta memoria.
Le app devono implementare delle callback che reagiscono ad alcuni eventi, come `onCreate`, `onLowMemory`, `onTrimMemory` e `onConfigurationChanged`.

Le app Android possono essere distribuite in due forme:
file Android Package Kit (APK) o
Android App Bundle (.aab).
La seconda forma fornisce tutte le risorse necessarie all'app, ma delega la generazione dell'APK e la sua firma a Google Play.
Le Bundle sono binari firmati che contengono il codice dell'app in diversi moduli.
Il modulo base contiene il core dell'app.
Il modulo base può essere esteso con diversi moduli che contengono nuove funzionalità/arricchimenti per l'app.
Puoi creare un'APK a partire da un AAB eseguendo il seguente comando:

`$ bundletool build-apks --bundle=/MyApp/my_app.aab --output=/MyApp/my_app.apks`

Se vuoi creare un'APK firmata da installare su un device di test, usa:

```
$ bundletool build-apks --bundle=/MyApp/my_app.aab --output=/MyApp/my_app.apks
--ks=/MyApp/keystore.jks
--ks-pass=file:/MyApp/keystore.pwd
--ks-key-alias=MyKeyAlias
--key-pass=file:/MyApp/key.pwd
```

Ogni app ha un AndroidManifest.xml che descrive la sua struttura, i suoi componenti (activity, service, content provider, intent receiver) e le permission richieste.
Contiene anche alcuni metadati, come l'icona dell'app, il numero di versione e il tema.
Potrebbe presentare altre informazioni, come le API compatibili e il tipo di storage sul quale può essere installato.

## App Components

Le activity sono la parte visibile delle app.
C'è un'activity per ogni screen, quindi un'app con tre screen diversi implementa tre diverse activity.
Contengono tutti gli elementi dell'interfaccia utente:
fragment, view e layout.
Gli stati dell'activity vengono gestisti facendo l'override dei metodi: `onCreate`, `onDestroy`, etc.
Di solito viene almeno implementato il primo.

Il fragment rappresenta il comportamento di una porzione dell'interfaccia utente con l'activity.
Hanno lo scopo di incapsulare parti di un'interfaccia per facilitare la riusabilità e l'adattamento a schermi di dimensione diversa.
Sono entità autonome nelle quali sono inclusi tutti i loro componenti.
Tuttavia devono essere integrati con le activity per essere utili.
L'activity gestisce i propri fragment tramite un Fragment Manager.

Le strutture di Inter-Process Communication permettono alle app di scambiarsi segnali in modo sicuro.
Invece di basarsi sulle strutture di IPC Linux, Android si basa su Binder, un'implementazione custom di OpenBinder.
Il framework di Binder usa un modello di comunicazione client-server.
Le app invocano i metodi IPC tramite un oggetto proxy.
L'oggetto proxy impacchetta i parametri che riceve e invia una transazione al server Binder, che è implementato come un character driver (`/dev/binder`).
Il server detiene un pool di thread per gestire le richieste e consegnare i messaggi all'oggetto destinazione.
Dal punto di vista dell'app, tutto ciò è una semplice chiamata di un metodo.
I servizi che permettono ad altre app di collegarsi sono chiamati bound service.
Il Servicemanager è un daemon di sistema che gestisce la registrazione e la ricerca di service di sistema.
Mantiene una lista di coppie nome/Binder per tutti i service registrati.
Puoi ottenere la lista dei service di sistema lanciando `$ adb shell service list`

Un intent messaging è un framework di comunicazione asincrona costruita su Binder.
Consente l'invio di messaggi point-to-point o secondo il paradigma publish-subscribe.
Un intent è un oggetto che può essere usato per richiedere un'azione da un componente di un'altra app.
Facilitano l'IPC, ma sono fondamentalmente usati per:

- avviare un'activity:
un'activity rappresenta un singolo screen in un'app.
Questo intent descrive l'activity e contiene i dati necessari
- avviare un service:
un service è un component che esegue operazioni in background, senza un'interfaccia utente
- consegnare un broadcast:
un broadcast è un messaggio che qualsiasi app può ricevere.
Il sistema consegna broadcast per eventi di sistema, tra cui il boot di sistema o l'avvio della ricarica

Gli intent espliciti indicano il componente che verrà avviato.
Gli intent impliciti vengono inviati al sistema operativo per eseguire una data azione su un insieme di dati.
È compito del sistema decidere quale app/classe svolgerà il particolare service.

Un intent filter specifica il tipo di intent che il componente vorrebbe ricevere.
Per esempio, dichiarando un intent filter per un'activity, si permette ad altre app di avviare direttamente l'activity con un certo tipo di intent.
Allo stesso modo, l'activity può solo essere avviata con un intent esplicito se non si è dichiarato nessun intent filter per essa.
Android usa gli intent per inviare messaggi in broadcast alle app (es. SMS), importanti informazioni sulla batteria (es. batteria scarica), cambiamenti di rete (es. perdita di connessione).

Per migliorare la sicurezza e la privacy, un Local Broadcast Manager è usato per inviare e ricevere intent all'interno di un app senza il bisogno di inviarli al sistema operativo.
È molto utile per garantire che dati sensibili e privati non escano dal perimetro dell'app.

I broadcast receiver sono componenti che permettono alle app di ricevere notifiche dalle altre app e dal sistema operativo.
Usandoli, le app possono reagire agli eventi.
Sono di solito usati per aggiornare l'interfaccia utente, avviare un servizio, aggiornare un contenuto, creare una notifica utente.
In AndroidManifest.xml va indicata un'associazione tra il broadcast receiver e un intent filter per specificare le action per le quali il receiver deve mettersi in ascolto.
Se non vengono dichiarati broadcast receiver, l'app non riceverà messaggi broadcast.
Le app non devono essere in esecuzione per ricevere gli intent; il sistema avvia automaticamente le app quando un intent rilevante viene richiamato.

Dopo aver ricevuto un intent implicito, Android farà una lista di tutte le app che hanno un action nei loro filter.
Se più di un app è stata registrata per la stessa action, Android chiederà all'utente quale app usare.
Si può usare un Local Broadcast Manager per assicurarsi che gli intent siano ricevuti solo dall'interno dell'app, e qualsiasi intent proveniente dall'esterno dell'app venga scartato.

Android usa SQLite per memorizzare i dati.
Esso non viene eseguito in un processo separato, ma è parte dell'app.
Di default il database di un'app è accedibile solo dall'app stessa.
I content provider offrono un meccanismo per astrarre le sorgenti di dati (database e file); inoltre forniscono un meccanismo standard ed efficiente per condividere i dati tra le app.
Per essere accessibili alle altre app, i content provider vanno dichiarati esplicitamente in AndroidManifest.xml.
Sono implementati secondo lo schema `content://model`.
I content provider offrono tutte le operazioni di un database: create, read, update, delete.
Quindi, una qualsiasi app con gli adeguati diritti nel suo manifest può manipolare i dati di altre app.

I service sono componenti di Android che eseguono task in background senza presentare un'interfaccia utente.
Sono pensati per andare in esecuzione per un lungo tempo.

Android fornisce un insieme di permission per alcuni task che l'app può richiedere.
Le permission sono classificate in base al livello di protezione e sono divise in:

- Normal:
livello più basso di protezione.
Dà all'app accesso a feature isolate a livello di app con rischio minimo per app, utente e sistema
es. `android.permission.INTERNET`
- Dangerous:
permette all'app di eseguire azioni che potrebbero impattare sulla privacy dell'utente o una normale operazione del device.
L'utente deve concedere esplicitamente questa permission.
es. `android.permission.RECORD_AUDIO`
- Signature:
concessa solo se l'app richiedente è stata firmata con lo stesso certificato dell'app che dichiara la permission.
es. `android.permission.ACCESS_MOCK_LOCATION`
- SystemOrSignature:
concessa solo ad app embedded nell'immagine di sistema o firmate con lo stesso certificato dell'app che ha dichiarato la permission.
es. `android.permission.ACCESS_DOWNLOAD_MANAGER`

## Signing and Publishing Process

Android supporta tre schemi di firma di applicazioni:

- JAR Signing (v1 Scheme):
tutti i file devono essere firmati con lo stesso certificato.
Questo schema non protegge alcune parti dell'APK, come i metadati ZIP.
L'inconveniente di questo schema è che l'APK verifier ha bisogno di processare strutture dati non fidate prima di applicare la firma, e il verifier scarta i dati non coperte dalle strutture dati.
Inoltre, l'APK verifier deve decomprimere tutti i file compressi, il chè richiede tempo e memoria
- APK Signature Scheme (v2 Scheme):
tutta l'APK viene firmata, e un APK Signing Block viene inserito nell'APK.
Durante la validazione, si controlla la firma su tutta l'APK.
Questa verifica è più veloce e offre una protezione globale contro le modifiche
- APK Signature Scheme (v3 Scheme):
usa lo stesso formato v2.
Aggiunge informazioni sulle versioni SDK supportate, una struct per proof-of-rotation all'APK signing block.
L'attributo di proof-of-rotation è una lista linked singolarmente, con ogni nodo contenente un certificato usato per firmare la versione precedente dell'app.
I vecchi certificati firmano il nuovo insieme di certificati, fornendo ogni nuova chiave con l'evidenza che dovrebbe essere fidata come le vecchie chiavi.

## Android Application Attack surface

La superficie di attacco per le app Android consiste in tutti i componenti dell'app, incluso il materiale necessario a rilasciarla e a supportarne il funzionamento.
L'app potrebbe essere vulnerabile se non:

- valida tutti gli input provenienti da comunicazioni IPC o URL-schema
- valida tutti gli input dell'utente
- comunica in modo sicuro con i server di backend
- memorizza in modo sicuro tutti i dati locali o carica dati non fidati dallo storage
- si protegge da ambienti compromessi, repackaging o altri attacchi locali

