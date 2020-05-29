# Cryptography for Mobile Apps

## Identifying Insecure and/or Deprecated Cryptographic Algorithms (MSTG-CRYPTO-4)

Algoritmi vulnerabili includono quelli di 
cifratura a blocchi (come DES, 3DES, blowfish), 
cifratura stream (come RC2, RC4), 
funzioni di hash (come MD4, MD5, SHA1) e 
generatori di numeri casuali (come Dual_EC_DRBG, SHA1PRNG).

Assicurati che:

- gli algoritmi di cifratura siano aggiornati e in linea con gli standard industriali.
Quelli insicuri vanno segnalati e dovrebbero essere rimossi dall'app e dal server.
- le lunghezze delle chiavi siano in linea con gli standard industriali e forniscano protezione per un sufficiente intervallo di tempo.
- i contesti crittografici non vadano mischiati: non si firma con la chiave pubblica, oppure non uso una coppia di chiavi già usata per la firma per fare cifratura.
- i parametri crittografici siano ben definiti.
Tra questi rientrano:
il salt crittografico dovrebbe essere almeno della stessa lunghezza dell'output della funzione di hash,
la password derivation function e l'iteration count dovrebbero essere ragionevoli,
gli IV devono essere casuali e unici,
usare i modi di cifratura a blocchi in base alle esigenze,
applicare un'adeguata gestione delle chiavi.

I seguenti algoritmi sono consigliati:

- confidentiality: AES-GCM-256 o ChaCha20-Poly1305
- integrity: SHA-256, SHA-384, SHA-512, Blake2
- firma digitale: RSA (3072 bit o superiore), ECDSA con NIST P-384
- scambio chiavi: RSA (3072 bit o superiore), DH (3072 bit o superiore), ECDH con NIST P-384

Inoltre, dovresti affidarti al secure hardware (se disponibile) per la memorizzazione di chiavi, l'esecuzione di operazioni crittografiche, etc.

## Common Configuration Issues (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3)

### Insufficient Key Length

Anche il più sicuro algoritmo di cifratura diventa vulnerabile ad attacchi di brute force quando si usa una chiave di lunghezza insufficiente.

### Symmetric Encryption with Hard-Coded Cryptographic Keys

Non memorizzare le chiavi segrete nello stesso posto in cui memorizzi i dati cifrati.
Gli sviluppatori commettono spesso l'errore di cifrare i dati memorizzati localmente con una chiave statica hard-coded e compilando tale chiave nell'app.
Ciò rende la chiave accessibile a chiunque possa usare un disassembler.
Assicurati che nessuna chiave sia memorizzata nel codice sorgente.

Se l'app usa la mutua autenticazione tramite certificati, assicurati che:
la password del certificato client non sia memorizzata localmente o sia bloccata nella KeyChain;
il certificato client non sia condivisio tra più installazioni.

Se l'app si basa su un container di cifratura aggiuntiva contenuto nei dati dell'app, controlla come viene usata la chiave di cifratura.
Se viene usato uno schema di key-wrapping, assicurati che il master secret venga inizializzato per ogni utente o che il container sia cifrato con una nuova chiave.
Se puoi usare il master secret o una password precedente per decifrare il container, controlla come viene gestito il cambio password.

Le chiavi segrete devono essere memorizzate nel secure device storage quando si usa la crittografia simmetrica nell'app.

### Weak Key Generation Functions

Assicurati che le password non siano passate direttamente alle funzioni di cifratura.
Invece, la password ricevuta dall'utente dovrebbe essere passata in una KDF per creare una chiave crittografica.
Scegli un'iteration count appropriato quando usi le password derivation function.

### Custom Implementations of Cryptography

Ispeziona tutti i metodi crittografici usati nel codice sorgente, specialmente quelli che vengono applicati direttamente ai dati sensibili.
Tutte le operazioni crittografiche dovrebbero usare API crittografiche standard per Android e iOS.
Qualsiasi operazione crittografica che non invoca routine standard da provider conosciuti dovrebbe essere analizzata attentamente.
Fai attenzione agli algoritmi standard che sono stati modificati.

In tutte le implementazioni crittografiche, devi assicurarti che:
le chiavi siano rimosse dalla memoria dopo il loro utilizzo;
lo stato interno dell'operazione di cifratura sia rimossa dalla memoria il prima possibile.

### Inadequate AES Configuration

Verifica che con AES non venga usato ECB ma CBC.
Si raccomanda l'uso di un modo che protegga anche l'integrità dei dati memorizzati, come Galois/Counter Mode (GCM).
Questo è obbligatorio in TLSv1.2, e quindi disponibile per tutte le moderne piattaforme.

Assicurati che l'IV sia generato usando un random number generator crittograficamente sicuro.

### Protecting Keys in Memory

Assicurati che tutte le azioni crittografiche e le chiavi restino nel Trusted Execution Environment (Keystore di Android) o Secure Enclave (Keychain).
Se le chiavi sono necessarie al di fuori del TEE/SE, assicurati di offuscarle/cifrarle e deoffuscarle/decifrarle solo quando devi usarle.
Ciò significa: sovrascrivi la struttura in memoria e tieni in mente che molti dei tipi Immutable in Android (es. BigInteger e String) restano nell'heap.

Data la facilità nel fare il dump della memoria, non condividere mai la stessa chiave tra account e device diversi, ad eccezione di chiavi pubbliche usate per la verifica della firma o cifratura.

### Protecting Keys in Transport

Assicurati che venga utilizzata la crittografia asimmetrica quando le chiavi vengono trasferite da un device all'altro o dall'app al back-end.

