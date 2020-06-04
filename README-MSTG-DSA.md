# Data Storage on Android

## Testing Local Storage for Sensitive Data (MSTG-STORAGE-1 and MSTG-STORAGE-2)

Le API di SharedPreferences sono di solito usate per memorizzare coppie chiave-valore.
I dati sono scritti in file XML in chiaro.
L'oggetto SharedPreferences può essere dichiarato accessibile a tutte le app o privato.
Il seguente codice crea un file key.xml.

```
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

Il contenuto del file è il seguente.

```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
	<string name="username">administrator</string>
	<string name="password">supersecret</string>
</map>
```

Username e password sono memorizzati in chiaro, e `MODE_WORLD_READABLE` rende il file accessibile a tutte le app.

L'SDK Android supporta il database SQLite.
Tuttavia le informazioni sensibili non vanno memorizzate in database non cifrati, come nell'esempio che segue.

```
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure",MODE_PRIVATE,null);
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

Usando la libreria SQLCipher, i database SQLite posson essere cifrati con password.

```
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

```
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

157
