# Local Authentication on Android

Con la local authentication l'app autentica l'utente tramite delle credenziali memorizzate localmente sul device.
Le credenziali possono essere un PIN, una password o un'impronta digitale.
É importante assicurarsi che l'autenticazione avvenga almeno tramite una primitiva crittografica.
Inoltre, si raccomanda che l'autenticazione sia verificata su un endpoint remoto.
I meccanismi offerti da Android sono:
il Confirm Credentials flow e 
il Biometric Authentication flow.

## Testing Confirm Credentials (MSTG-AUTH-1 and MSTG-STORAGE-11)

Se l'utente si è loggato recentemente sul device, allora Confirm Credentials può essere usato per sbloccare il materiale crittografico dall'`AndoidKeystore`.
Questo avviene se l'utente ha sbloccato il device entro un certo limite di tempo (`setUserAuthenticationValidityDurationSeconds`), diversamente deve sbloccare di nuovo il device.

La sicurezza del Confirm Credentials è forte tanto quanto la protezione impostata per il blocco schermo.
Dato che spesso i pattern di sblocco schermo sono predicibili, non si raccomanda l'uso di Confirm Credentials per app che richiedono un doppio livello di sicurezza.

### Static Analysis

Assicurati che il blocco schermo sia stato impostato:

```java
KeyguardManager mKeyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);

if (!mKeyguardManager.isKeyguardSecure()) {
	// Show a message that the user hasn't set up a lock screen.
}
```

- crea la chiave protetta con il blocco schermo.
Per poter usare questa chiave l'utente deve aver sbloccato il device negli ultimi X secondi, o dovrà sbloccare di nuovo il device.
Assicurati che questo timeout non sia troppo lungo, dato che è più difficile assicurare che l'utente che sta usando l'app sia lo stessso che ha sbloccato il device:

```java
try {
	KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
	keyStore.load(null);
	KeyGenerator keyGenerator = KeyGenerator.getInstance(
		KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

	// Set the alias of the entry in Android KeyStore where the key will appear
	// and the constrains (purposes) in the constructor of the Builder
	keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
		KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
		.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
		.setUserAuthenticationRequired(true)
		// Require that the user has unlocked in the last 30 seconds
		.setUserAuthenticationValidityDurationSeconds(30)
		.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
		.build());

	keyGenerator.generateKey();
} catch (NoSuchAlgorithmException | NoSuchProviderException
		| InvalidAlgorithmParameterException | KeyStoreException
		| CertificateException | IOException e) {
	throw new RuntimeException("Failed to create a symmetric key", e);
}
```

- imposta il lock screen per la conferma:

```java
private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1; 
//used as a number to verify whether this is where the activity results from
Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);

if (intent != null) {
	startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
}
```

- usa la chiave dopo lo sblocco dello schermo

```java
@Override
protected void onActivityResult(int requestCode, int resultCode, Intent data) {
	if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
		// Challenge completed, proceed with using cipher
		if (resultCode == RESULT_OK) {
			//use the key for the actual authentication flow
		} else {
			// The user canceled or didn’t complete the lock screen
			// operation. Go to error/cancellation flow.
		}
	}
}
```

Assicurati che la chiave sbloccata venga usata durante l'esecuzione dell'app.
Per esempio, la chiave potrebbe essere usata per decifrare il local storage o un messaggio ricevuto da un endpoint remoto.
Se l'app controlla semplicemente se l'utente ha sbloccato la chiave o meno, la local authentication potrebbe essere raggirata.

### Dynamic Analysis

Applica una patch all'app o esegui l'instrumentation per raggirare l'autenticazione tramite impronta digitale.
Per esempio, potresti usare Frida per invocare direttamente la callback `onActivityResult` per vedere se il materiale crittografico può essere ignorato nel local authentication flow.

## Testing Biometric Authentication (MSTG-AUTH-8)

L'accesso all'hardware viene fornito tramite la classe `FingerprintManager`.
L'app ne istanzia un oggetto e invoca il metodo `authenticate`.
Questo metodo tuttavia non è una prova forte che l'autenticazione tramite impronte digitali sia stata effettivamente attuata; per esempio l'autenticazione può essere patched da un attaccante oppure il metodo potrebbe restituire success tramite hooking.

Si applica una sicurezza migliore combinando l'uso delle fingerprint API con la classe `KeyGenerator`.
In questo modo, viene memorizzata una chiave simmetrica nel KeyStore e viene sbloccata con le impronte digitali dell'utente.
Per esempio, per abilitare l'accesso a un servizio remoto, viene creata una chiave AES con la quale si cifra il PIN dell'utente o l'authentication token.
Invocando `setUserAuthenticationRequired(true)` alla creazione della chiave, si assicura che l'utente debba riautenticarsi per recuperarla.
Le credenziali di autenticazione cifrate possono poi essere salvate direttamente sul device (es. `SharedPreferences`).
Questa modalità è relativamente sicura per assicurarsi che l'utente abbia effettivamente inserito un'impronta digitale autorizzata.
Inoltre è necessario che l'app tenga la chiave simmetrica in memoria durante le operazioni crittografiche, esponendola potenzialmente agli attaccanti che possono accedere alla memoria dell'app durante l'esecuzione.

Un metodo ancora più sicuro è l'uso della crittografia asimmetrica.
L'app crea una coppia di chiavi asimmetriche nel KeyStore e registra la chiave pubblica sul server.
Le transazioni sono firmate con la chiave privata e verificate dal server con la chiave pubblica.
Il vantaggio è che le transazioni possono essere firmate tramite le Keystore API senza estrarre la chiave privata dal KeyStore.
Quindi per gli attaccanti è impossibile estrarre la chiave dai dump di memoria o tramite hooking.

Ci sono alcune SDK che forniscono supporto biometrico ma che hanno le loro vulnerabilità.
Fai attenzione quando usi SDK di terze parti per gestire la logica di autenticazione sensibile.

### Static Analysis

Cerca le chiamate `FingerprintManager.authenticate`.
Il primo parametro dovrebbe essere un'istanza di `CryptoObject`.
Se invece fosse impostato a `null`, l'autorizzazione tramite impronte digitali sarebbe puramente event-bound, ciò creerebbe un problema di sicurezza.

La chiave usata per inizializzare il `CryptoObject` deve essere stata creata usando la classe `KeyGenerator` e invocando `setUserAuthenticationRequired(true)` durante la sua creazione sull'oggetto `KeyGenParameterSpec`.

Assicurati di verificare la logica di autenticazione.
L'endpoint remoto deve costringere il client a presentare il segreto recuperato dal KeyStore, un valore derivato dal segreto, o un valore firmato con la chiave privata del client.

Per implementare l'autenticazione tramite impronte digitali in modo sicuro bisogna innanzitutto controllare se tale tipo di autenticazione è disponibile.
Il device deve avere almeno Android 6.0.
Bisogna anche verificare i seguenti prerequisiti:

- le permission devono essere richieste nell'Android Manifest

```xml
<uses-permission android:name="android.permission.USE_FINGERPRINT" />
```

- l'hardware adatto deve essere disponibile

```java
FingerprintManager fingerprintManager = (FingerprintManager)
	context.getSystemService(Context.FINGERPRINT_SERVICE);

fingerprintManager.isHardwareDetected();
```

- l'utente deve avere il blocco schermo attivo

```java
KeyguardManager keyguardManager = (KeyguardManager)
	context.getSystemService(Context.KEYGUARD_SERVICE);

keyguardManager.isKeyguardSecure();
//note if this is not the case: ask the user to setup a protected lock screen
```

- almeno un'impronta digitale deve essere registrata

```java
fingerprintManager.hasEnrolledFingerprints();
```

- l'app deve avere i permessi per chiedere l'impronta digitale

```java
context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PermissionResult.PERMISSION_GRANTED;
```

Se uno qualsiasi dei precedenti controlli non è verificato, l'opzione di autenticazione tramite impronte digitali non dovrebbe essere usata.

Bisogna tener conto che non tutti i device Android offrono un key storage hardware.
La classe `KeyInfo` può essere usata per verificare se la chiave risiede in hardware sicuro come TEE o SE.

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance(getEncryptionKey().getAlgorithm(), ANDROID_KEYSTORE);

KeyInfo secetkeyInfo = (KeyInfo) factory.getKeySpec(yourencryptionkeyhere, KeyInfo.class);

secetkeyInfo.isInsideSecureHardware()
```

Su alcuni sistemi, è possibile imporre la policy per l'autenticazione biometrica attraverso l'hardware.

```java
keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware();
```

### Fingerprint Authentication using a Symmetric Key

L'autenticazione tramite impronte digitali può essere implementata creando una nuova chiave AES usando la classe `KeyGenerator` e aggiungendo `setUserAuthenticationRequired(true)` nel `KeyGenParameterSpec.Builder`.

```java
generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);

generator.init(new KeyGenParameterSpec.Builder (KEY_ALIAS,
	KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
	.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
	.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
	.setUserAuthenticationRequired(true)
	.build()
);

generator.generateKey();
```

Per cifrare e decifare tramite la chiave protetta, crea un oggetto `Cipher` e inizializzalo con l'alias della chiave.

```java
SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

if (mode == Cipher.ENCRYPT_MODE)
	cipher.init(mode, keyspec);
```

Considera che una nuova chiave non può essere usata immediatamente, deve prima essere autenticata tramite `FingerprintManager`.

```java
cryptoObject = new FingerprintManager.CryptoObject(cipher);
fingerprintManager.authenticate(cryptoObject, new CancellationSignal(), 0, this, null);
```

Quando l'autenticazione ha successo, viene invocata la callback `onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result)`.

```java
public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
	cipher = result.getCryptoObject().getCipher();
	//(... do something with the authenticated cipher object ...)
}
```

### Fingerprint Authentication using an Asymmetric Key Pair

Per implementare l'autenticazione con impronte digitali usando la crittografia asimmetrica, prima crea una coppia di chiavi usando la classe `KeyPairGenerator` e registra la chiave pubblica sul server.
Puoi autenticare i dati firmandoli sul client e verificando la firma sul server.

Una coppia di chiavi viene generata come segue:

```java
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

keyPairGenerator.initialize(
	new KeyGenParameterSpec.Builder(MY_KEY,
	KeyProperties.PURPOSE_SIGN)
	.setDigests(KeyProperties.DIGEST_SHA256)
	.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
	.setUserAuthenticationRequired(true)
	.build());

keyPairGenerator.generateKeyPair();
```

Per usare la chiave per firmare, devi instanziare un CryptoObject e autenticarlo tramite il `FingerprintManager`.

```java
Signature.getInstance("SHA256withECDSA");
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
PrivateKey key = (PrivateKey) keyStore.getKey(MY_KEY, null);
signature.initSign(key);
CryptoObject cryptObject = new FingerprintManager.CryptoObject(signature);

CancellationSignal cancellationSignal = new CancellationSignal();
FingerprintManager fingerprintManager =
	context.getSystemService(FingerprintManager.class);
fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
```

Puoi firmare il contenuto di un byte array come segue:

```java
Signature signature = cryptoObject.getSignature();
signature.update(inputBytes);
byte[] signed = signature.sign();
```

- Se le transazioni vengono firmate, è necessario generare un nonce random e aggiungerlo ai dati da firmare.
Diversamente, un attaccante potrebbe fare il replay della transazione
- per implementare l'autenticazione usando l'autenticazione simmetrica con impronte digitali, usare un protocollo challenge-response.

### Additional Security Features

Da Android 7.0 è possibile usare il metodo `setInvalidatedByBiometricEnrollment(boolean invalidateKey)` su `KeyGenParameterSpec.Builder`.
Quando `invalidateKey` viene impostato a `true` (di default), le chiavi che sono valide per un'autenticazine con impronte digitali diventano invalide quando viene registrata una nuova impronta digitale.
Ciò impedisce a un attaccante di recuperare la chiave anche se sono capaci di registrare una nuova impronta digitale.
Android 8.0 aggiunge due codici di errore:

- `FINGERPRINT_ERROR_LOCKOUT_PERMANENT`: l'utente ha provato troppe volte a sbloccare il device usando il lettore di impronte digitali
- `FINGERPRINT_ERROR_VENDOR`: si è verificato un errore del lettore del particolare vendor

### Third party SDKs

Assicurati che l'autenticazione tramite impronte digitali e/o altri tipi di autenticazione biometrica avvengano sulla base dell'Android SDK e delle sue API.
Se ciò non avviene, assicurati che le SDK alternative siano state adeguatamente esaminate per eventuali debolezze.
Assicurati che l'SDK sia supportata dal TEE/SE che sblocca il segreto crittografico sulla base dell'autenticazione biometrica.
Questo segreto non dovrebbe essere sbloccato da nessun altro, tranne che da un'entry biometrica.
In questo modo, la logica dell'impronta digitale non può essere aggirata.

### Dynamic Analysis

Applica una patch all'app o usa l'instrumentation per raggirare l'autenticazione tramite impronte digitali sul client.
Per esempio, potresti usare Frida per invocare direttamente la callback `onAuthenticationSucceeded`.
