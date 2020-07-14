# Android Cryptographic APIs

## Testing the Configuration of Cryptographic Standard Algorithms (MSTGCRYPTO-2, MSTG-CRYPTO-3 and MSTG-CRYPTO-4)

Le API crittografiche Android sono basate su Java Cryptography Architecture (JCA).
JCA specifica le interfacce e la loro implementazione, permettendo di usare security provider diversi che implementano gli algoritmi crittografici.
I provider cambiano in base a versione Android e a build specifica dell'OEM.

Per applicazioni che supportano versioni più vecchie di Android di solito si usa Spongy Castle.

Android SDK fornisce dei meccanismi per specificare la generazione e l'uso di chiavi sicure.


```java
String keyAlias = "MySecretKey";

KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
	.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
	.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
	.setRandomizedEncryptionRequired(true)
	.build();

KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
keyGenerator.init(keyGenParameterSpec);

SecretKey secretKey = keyGenerator.generateKey();
```

`KeyGenParameterSpec` indica che la chiave può essere usata per la cifratura e la decifratura, ma non per altri scopi (es. firma o verifica).
Inoltre specifica la modalità (CBC), il padding (PKCS #7), e specifica esplicitamente che è richiesta la cifratura random (di default).
`AndroidKeyStore` è il nome del service provider crittografico.
In questo modo le chiavi sono automaticamente memorizzate nell'`AndroidKeyStore`, che beneficiano della sua protezione.

GCM è una modalità AES, che oltre a essere crittograficamente più sicura delle altre, fornisce anche l'autenticazione.
Usando CBC è necessario applicarla separatamente, usando HMAC.
GCM è l'unica modalità AES che non supporta il padding.
Il seguente codice usa la chiave per cifrare.

```java
String AES_MODE = KeyProperties.KEY_ALGORITHM_AES
	+ "/" + KeyProperties.BLOCK_MODE_CBC
	+ "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;
KeyStore AndroidKeyStore = AndroidKeyStore.getInstance("AndroidKeyStore");

// byte[] input
Key key = AndroidKeyStore.getKey(keyAlias, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
cipher.init(Cipher.ENCRYPT_MODE, key);

byte[] encryptedBytes = cipher.doFinal(input);
byte[] iv = cipher.getIV();
// save both the IV and the encryptedBytes
```

Segue il codice per decifrare.

```java
// byte[] input
// byte[] iv
Key key = AndroidKeyStore.getKey(AES_KEY_ALIAS, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
IvParameterSpec params = new IvParameterSpec(iv);
cipher.init(Cipher.DECRYPT_MODE, key, params);

byte[] result = cipher.doFinal(input);
```

### Static Analysis

Individua le primitive crittografiche nel codice.
Le classi e le interfacce più usate sono:
Cipher,
Mac,
MessageDigest,
Signature,
Key,
PrivateKey,
PublicKey,
SecretKey,
e altre nei package `java.security.*` e `javax.crypto.*`.

## Testing Random Number Generation (MSTG-CRYPTO-6)

In generale andrebbe usato `SecureRandom`.

### Static Analysis

Individua tutte le istanze di generatori di numeri casuali e cerca classi custom o insicure come `java.util.Random`.
Questa classe genera una sequenza identica di numeri dato uno stesso seed; quindi, la sequenza numeri è predicibile.
Identifica tutte le istanze di `SecureRandom` che non sono create usando il costruttore di default.
Specificando il seed si riduce la randomness.

### Dynamic Analysis

Una volta che l'attaccante conosce quale PRNG è usato, può essere banale creare un PoC per ottenere il prossimo valore causale sulla base di quelli precedentemente osservati.
L'approccio raccomandato è decompilare l'APK e applicare la Static Analysis.

Puoi usare il Sequencer di BURP per verificare la randomness.

## Testing Key Management (MSTG-STORAGE-1, MSTG-CRYPTO-1 and MSTGCRYPTO-5)

Il metodo più sicuro di gestire le chiavi è semplicemente non memorizzarle mai sul device.
Ciò significa che bisogna chiedere una passphrase all'utente ogni volta che l'app deve eseguire operazioni crittografiche.
Anche se non è l'implementazione ideale da un punto di vista dell'user experience, è il metodo più sicuro di gestire le chiavi.
In questo modo le chiavi sono disponibili in memoria in un array solo quando sono usate.
Nessuna chiave viene scritta sul file system  e nessuna passphrase viene memorizzata.
Tuttavia, alcune cipher non puliscono adeguatamente i loro array di byte.
Inoltre, fai attenzione quando provi ad azzerare la chiave.

Una chiave di cifratura simmetrica può essere generata da una passphrase usando Password Based Key Derivation Function version 2 (PBKDF2).
Il seguente codice mostra come generare una chiave di cifratura forte basata su una password.

```java
public static SecretKey generateStrongAESKey(char[] password, int keyLength) {
	//Initiliaze objects and variables for later use
	int iterationCount = 10000;
	int saltLength = keyLength / 8;
	SecureRandom random = new SecureRandom();

	//Generate the salt
	byte[] salt = new byte[saltLength];
	random.nextBytes(salt);

	KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
	SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
	return new SecretKeySpec(keyBytes, "AES");
}
```

Il salt può essere memorizzato privatamente nelle `SharedPreferences`.
Si raccomanda di escludere il salt da Android backup per impedire la sincronizzazione di dati sensibili.
Se un device rooted o non patched, o un'app patched rientra nei rischi allora sarebbe meglio cifrare il salt con un chiave nell'`AndroidKeystore`.
Da Android 8.0 è consigliabile usare `PBKDF2withHmacSHA256`.

L'Android Keystore API è stata sviluppata per fornire storage sicuro per le chiavi.
Solo l'app ha accesso alle chiavi che essa stessa genera.
Da Android 6.0 viene imposto che l'AndroidKeyStore sia implementato in hardware quando è presente un sensore per le impronte digitali.
Ciò significa che un chip crittografico o un Trusted Platform Module (TPM) viene usato per gestire le chiavi.

La metodologia generale è cifrare le chiavi simmetriche con la chiave pubblica e memorizzare la chiave privata nell'`AndroidKeyStore`.
La chiave simmetrica cifrata viene memorizzata in modo sicuro nelle `SharedPreferences`.
Quando l'app necessita della chiave simmetrica, preleva la chiave privata dall'`AndroidKeyStore` e decifra la chiave simmetrica.
Quando le chiavi sono generate e usate all'interno dell'`AndroidKeyStore` e il `KeyInfo.isinsideSecureHardware` restituisce true, allora non è possibile fare il dump delle chiavi o monitorare le sue operazioni crittografiche.

### Secure Key Import into Keystore

Android 9 consente di importare chiavi in modo sicuro nell'`AndroidKeystore`.
`AndroidKeystore` genera una coppia di chiavi (`PURPOSE_WRAP_KEY`), che sono protette con un certificato.
Questa coppia di chiavi serve a proteggere la chiave da importare nell'`AndroidKeystore`.
La chiave cifrata con la chiave pubblica del certificato è generata come messaggio ASN.1-encoded nel formato `SecureKeyWrapper` che contiene anche una descrizione del modo in cui la chiave da importare può essere usata.
La chiave viene poi decifrata nell'hardware dell'`AndroidKeystore` del device.
In questo modo la chiave non è mai in cleartext nella memoria del device.

La sicurezza delle chiavi è influenzata da:

- parametro `algorithm`: specifica l'algoritmo crittografico con cui la chiave viene usata
- parametro `keySize`: specifica la dimensione, in bit, della chiave
- parametro `digest`: specifica gli algoritmi di digest con i quali la chiave può essere usata per le operazioni di firma e di verifica

### Key Attestation

La Key Attestation dà maggiore confidenza sul fatto che le chiavi usate all'interno dell'app siano memorizzate nel keystore hardware del device.

Specificando l'alias della coppia di chiavi si ottiene la catena di certificati, che puoi usare per verificare le proprietà di tale coppia.
Se il root certificate della catena è il Google Hardware Attestation Root certificate e vengono eseguiti i controlli relativi alla coppia a livello hardware, c'è la sicurezza che il device supporti la key attestation a livello hardware e la chiave sia nel keystore hardware che Google considera sicuro.
Diversamente, se la catena ha un root certificate diverso, Google non segnala nulla sulla sicurezza dell'hardware.

Anche se il processo di key attestation può essere implementato direttamente all'interno dell'app, per ragioni di sicurezza è consigliato che sia implementato lato server.
Le linee guida per l'implementazione della key attestation sono:

- il server dovrebbe inizializzare il processo di key attestation creando in modo sicuro un numero casuale usando un Cryptographically Secure Random Number Generator (CSPRNG) e inviarlo all'utente come challenge
- il client dovrebbe invocare l'API `setAttestationChallenge` con la challenge ricevuta dal server e dovrebbe recuperare l'attestation certificate chain usando il metodo `KeyStore.getCertificateChain`
- l'attestation response dovrebbe essere inviato al server per la verifica e i controlli successivi dovrebbero essere eseguiti per la verifica della key attestation response:
	- verificare la certificate chain, fino alla root ed eseguire controlli di sanity check come validità, integrità e attendibilità
	- controllare se il certificato è firmato con la Google attestation root key che rende il processo di attestation attendibile
	- estrarre il primo elemento dall'attestation certificate chain ed eseguire i seguenti controlli:
		- verifica che l'attestation challenge ha lo stesso valore che era stato generato lato server
		- verificare la firma della key attestation response
		- controllare il livello di sicurezza  del Keymaster per determinare se il device ha un meccanismo di key storage sicuro.
		Il Keymaster è un pezzo di software che viene eseguito nel security context ed espone tutte le operazioni del keystore.
		Il livello di sicurezza può essere: `Software`, `Trustedenvironment` o `StrongBox`.
		- inoltre, puoi controllare il livello di sicurezza per verificare come l'attestation certificate è stato generato.
		Altri controlli riguardanti le chiavi possono essere lo scopo, il tempo di accesso, i requisiti di autenticazione

Un tipico Android Keystore attestation response contiene i seguenti parametri:
`fmt`: format identifier,
`authData`: authenticator data per l'attestation,
`alg`: algoritmo usato per la signature,
`sig`: signature,
`x5c`: attestation certificate chain.

`sig` viene generata concatenando `authData` e `clientDataHash` (challenge ricevuta dal server) e firmando il tutto con la chiave privata con l'algoritmo `alg`.
Inoltre `sig` è verificato lato server usando la chiave pubblica contenuta nel certificato.

Da un punto di vista dell'analisi di sicurezza l'analista potrebbe eseguire i seguenti controlli sull'implementazione:

- controllare se la key attestation è completamente implementata lato client.
In questo caso può essere aggirata modificando l'app o facendone l'hooking
- controllare se il server usa challenge random durante la key attestation.
Diversamente l'implementazione potrebbe essere vulnerabile a replay attack.
Inoltre dovrebbero essere eseguiti controlli sull'effettiva randomness della challenge generata
- controlla se il server verifica l'integrità della key attestation response
- controlla se il server esegue i controlli di base come verifica di integrità, verifica della fiducia, validità sulla catena dei certifiati

### Decryption only on Unlocked Devices

Da Android 9 il flag `unlockedDeviceRequred` impedisce che le chiavi memorizzate nell'`AndroidKeystore` vengano decifrate quando il device è bloccato, e richiede che lo schermo venga sbloccato prima di decifrarle.

### StrongBox Hardware Security Module

I device con Android 9 e superiori possono avere uno `Strongbox Keymaster`, un'implementazione del Keymaster HAL che risiede in un HSM che ha la sua CPU, il suo Secure Storage, un generatore di numeri casuali vero e proprio e un meccanismo per resistere alla modifica dei pacchetti.

### Key Use Authorization

Per mitigare l'uso non autorizzato di chiavi sul device, Android Keystore permette alle app di specificare gli usi autorizzati delle chiavi al momento della creazione o dell'importazione.
Una volta eseguita tale operazione, le autorizzazioni non possono essere cambiate.

Un'altra API offerta da Android è la `KeyChain`, che dà accesso alle chiavi private e alle loro catene di certificati.
Di solito non viene usata a causa delle interazioni necessarie e la natura condivisa della Keychain.

Un modo leggermente meno sicuro di memorizzare le chiavi crittografiche, è nelle SharedPreferences di Android.
Quando sono inizializzate in `MODE_PRIVATE`, il file è leggibile solo dall'app che l'ha creato.
Tuttavia, su un device rooted qualsiasi app con accesso root può leggere il file di SharedPreferences di altre app, indipendentemente da `MODE_PRIVATE`.
Non è il caso di Android Keystore, il cui accesso è gestito a livello kernel, che richiede molto più lavoro e abilità per raggirare senza ripulire il Keystore o distruggere le chiavi.

Le ultime tre opzioni sono 
l'uso di chiavi di cifratura hardcoded nel codice sorgente, 
l'uso di una key derivation function predicibile basata su attributi predicibili oppure 
la memorizzazione di chiavi in posizioni pubbliche come `/sdcard/`.
Ovviamente le chiavi di cifratura hardcoded sono da evitare.
Tutte le istanze dell'app userebbero le stesse chiavi.
Nel caso di una key derivation function predicibile basa su attributi predicibili che sono accedibili da altre app, l'attaccante deve solo trovare la KDF e applicarla sul device per trovare la chiave.
La memorizzazione in posizioni pubbliche espone le chiavi alle app che hanno i permessi per leggere la partizione pubblica e rubare le chiavi.

### Static Analysis

Individua gli usi delle primitive crittografiche nel codice.
Le classi e le interfacce maggiormente utilizzate sono:
Cipher,
Mac,
MessageDigest,
Signature,
AndroidKeyStore,
Key,
PrivateKey,
PublicKey,
SecretKeySpec,
KeyInfo,
e altre nei package `java.security.*` e `javax.crypto.*`.


Vediamo un esempio per individuare una chiave di cifratura hardcoded.
Disassambla il DEX bytecode in Smali bytecode usando `Backmali`.

```sh
$ backsmali d file.apk -o smali_output/
```

Cerca la classe `SecretKeySpec` nel bytecode.

```sh
$ grep -r "Ljavax\crypto\spec\SecretKeySpec;" smali_output/*
```

Se hai accesso al codice sorgente, verifica almeno i seguenti punti:

- controlla quale meccanismo è usato per memorizzare una chiave:
privilegiare `AndroidKeyStore` rispetto alle altre soluzioni
- controlla se i meccanismi di defense in depth sono usati per assicurae l'uso di un TEE
- in caso di soluzioni crittografiche whitebox: studiarne l'efficacia o consultare uno specialista dell'area
- verificare gli scopi della chiave, per esempio:
	- assicurarsi che per chiavi asimmetriche, la chiave privata sia esclusivamente usata per firmare e la chiave pubblica sia usata per la cifratura
	- assicurarsi che le chiavi simmetriche non siano riusate per scopi multipli; una nuova chiave simmetrica dovrebbe essere generata se è usata in un contesto diverso

### Dynamic Analysis

Eseguire l'hooking dei metodi crittografici e analizzare le chiavi che sono state usate.
Monitora l'accesso al file system durante le operazioni crittografiche per verificare dove vengono scritte o lette le chiavi.
