# Mobile App Authentication Architectures

L'autenticazione può essere basata su uno o più dei seguenti fattori:

- qualcosa che l'utente conosce (pwd, PIN, pattern)
- qualcosa che l'utente ha (SIM card, OTP generator, token hardware)
- qualcosa che l'utente è (impronte digitali, retina, voce)

L'autenticazione username/password (combinata con una password policy ragionevole) è generalmente considerata sufficiente per app che non gestiscono dati troppo sensibili.
Per app sensibili è opportuno aggiungere un secondo fattore di autenticazione.

Per app non critiche, il MASVS presenta i seguenti requisiti:

- se l'app fornisce accesso remoto agli utenti, è necesaria almeno l'autenticazione con username/password
- esiste una password policy e viene imposta sull'endpoint remoto
- l'endpoint remoto implementa un lock temporaneo dell'account, quando credenziali di autenticazione errate sono immesse in un breve lasso di tempo

Per app critiche, il MASVS aggiunge i seguenti requisiti:

- un secondo fattore di autenticazione viene applicato sull'endpoint remoto e il requisito di 2FA viene imposto
- l'autenticazione successiva è richiesta per eseguire operazioni che trattano dati o transazioni sensibili
- l'app informa l'utente delle attività recenti del suo account quando esegue il login

## Stateful vs. Stateless Authentication

Con l'**autenticazione stateful**, un session id unico è generato quando l'utente accede.
Nelle richieste successive questo session id è usato come riferimento ai dati dell'utente memorizzati sul server.
Il session id è opaco, non contiene alcun dato dell'utente.

Con l'**autenticazione stateless**, tutte le informazioni che identificano l'utente sono memorizzate in un token mantenuto sul client.
Il token può essere passato a qualsiasi server o micro servizio, eliminando la necessità di mantenere lo stato della sessione sul server.
L'autenticazione stateless è spesso gestita tramite un authorization server, che produce, firma, e opzionalmente cifra il token dopo l'accesso dell'utente.

L'autenticazione stateful è quella maggiormente diffusa, ma quella stateless si sta diffondendo per vari motivi:
migliora la scalabilità e le performance eliminando la necessità di memorizzare lo stato della sessione sul server;
i token permettono agli sviluppatori di sdoppiare l'autenticazione dall'app, infatti i token sono generati dall'authorization server e lo schema di autenticazione può essere cambiato facilmente.

Gli schemi di autenticazione sono a volte supportati dall'autenticazione contestuale passiva, che può sfruttare:
geolocalizzazione, indirizzo IP, orario, dispositivo usato.
Il constesto dell'utente viene confrontato con i dati precedentemente memorizzati per identificare anomalie che potrebbero indicare account compromessi o potenziali truffe.

## Verifying that Appropriate Authentication is in Place (MSTG-ARCH-2 and MSTG-AUTH-1)

- identifica i fattori di autenticazione addizionali che l'app usa
- individua tutti gli endpoint che forniscono funzionalità critiche
- verifica che tutti i fattori addizionali siano applicati rigorosamente su tutti gli endpoint

Le vulnerabiltà nei meccanismi di autenticazione si hanno
quando lo stato dell'autenticazione non è imposto in modo consistente sul server e quando il client può modificare lo stato.
Mentre il servizio di backend sta elaborando le richieste dal client mobile, deve effettuare i controlli di autorizzazione: verificare che l'utente sia loggato e autorizzato per ogni risorsa richiesta.

## Testing Best Practices for Passwords (MSTG-AUTH-5 and MSTG-AUTH-6)

### Static Analysis

Verifica l'esistenza di una password policy e i requisiti di implementazione.
Identifica tutte le funzioni relative alla password nel codice sorgente e assicurati che i controlli siano eseguiti in ognuna di esse.

Verifica se il codice sorgente presenta una procedura di throttling: 
un contatore per tentativi di login effettuati in un periodo di tempo ridotto per un dato username e un dato metodo,
per impedire ulteriori tentativi di login dopo che una soglia è stata raggiunta.
In seguito a un login corretto, il contatore va resettato.
Cerca di seguire le seguenti best practice:

- dopo pochi tentativi di login errati, l'account obiettivo dovrebbe essere bloccato
- di solito si usa un blocco di 5 minuti
- i controlli vanno effettuati lato server
- i tentativi di login errati devono essere collegati all'account e non alla particolare sessione

### Dynamic Analysis

Usa l'Intruder di BURP per verificare il meccanismo di throttling.

## Testing Stateful Session Management (MSTG-AUTH-2)

Individua gli endpoint che forniscono informazioni o funzioni sensibili e verifica se i meccanismi di autorizzazione sono imposti in modo consistente.
Il servizio di backend deve verificare il session id o il token dell'utente e verificare che l'utente abbia i privilegi sufficienti per accedere alla risorsa.
Se il session id o il token non è presente o non è valido, la richiesta deve essere rifiutata.

Assicurati che:

- i session id siano generati in modo casuale lato server
- i session id non siano facilmente indovinabili
- i session id siano scambiati su connessioni sicure
- l'app non memorizzi i session id sullo storage
- il server verifichi il session id quando l'utente prova ad accedere a elementi applicativi privilegiati
- la sessione è terminata lato server e le informazioni della sessione vengono eliminate nell'app, dopo un certo time out o quando l'utente esegue il log out

L'autenticazione non dovrebbe essere implementata da zero ma costruita su framework già esistenti.

## Testing Session Timeout (MSTG-AUTH-7)

### Static Analysis

Il timeout raccomandato dalla documentazione dei vari framework potrebbe variare dai 10 minuti alle 2 ore.

### Dynamic Analysis

Accedi a una risorsa che richiede autorizzazione.
Esegui accessi successivi incrementando il ritardo di 5 minuti.
Nel momento in cui la risorsa non è più raggiungibile, la sessione è andata in timeout.

In BURP puoi automatizzare la verifica utilizzando l'estensione `Session Timeout Test`.

## Testing User Logout (MSTG-AUTH-4)

L'obiettivo è verificare che al logout il session id e il token siano invalidati sia lato server che lato client, 
in modo da evitare che possano essere utilizzati dall'attaccante per accedere per conto dell'utente.

### Static Analysis

Verifica che le funzionalità di logout terminino correttamente la sessione, in base alla tecnologia usata.
In caso di autenticazione stateless, se sono usati token devono essere eliminati dal dispositivo mobile.

### Dynamic Analysis

Accedi a una risorsa che richiede autenticazione.
Esegui il logout.
Riaccedi alla risorsa.
Se ricevi la stessa risposta ottenuta prima del logout, il session id o il token è ancora valido.

## Testing Two-Factor Authentication and Step-up Authentication (MSTG-AUTH-9 and MSTG-AUTH-10)

Quando l'utente accede a informazioni sensibili viene applicata la 2FA.
Di solito si usa username/password per il primo fattore e uno dei seguenti per il secondo:

- OTP via SMS
- one-time code tramite chiamata
- token hardware o software
- push notification combinata con PKI e autenticazione locale

La seconda autenticazione può essere eseguita al login o nel momento in cui l'utente cerca di eseguire operazioni più sensibili (es. bonifico).

Dal 2016 il NIST consiglia di valutare autenticatori alternativi all'OTP via SMS. Le possibili minacce derivanti dal suo utilizzo sono:
intercettazione wireless (l'attaccante può intercettare gli SMS sfruttando femtocelle e altre vulnerabilità),
trojan (inoltra il testo dell'SMS a un altro numero o backend),
attacco SIM SWAP (l'attaccante chiamando la compagnia telefonica o lavorando presso essa è in gradi di trasferire il numero della vittima su un'altra SIM),
attacco Verification Code Forwarding (attacco di social engineering che sfrutta la fiducia dell'utente nell'entità che fornisce l'OTP, la vittima riceve un codice e le viene richiesto di inoltrarlo usando lo stesso mezzo col quale ha ricevuto l'informazione),
segreteria telefonica (in alcuni casi se l'OTP non viene usato, viene registrato un messaggio nella segreteria telefonica, l'attaccante compromettendola può avere accesso all'account della vittima).

Per mitigare queste minacce è possibile:
indicare le azioni da fare se l'OTP non è stato richiesto e indicare che l'azienda non chiederà mai di inoltrere password o codici;
inviare l'OTP su canali dedicati, quindi applicazioni usate solo per questa funzione e non accessibili ad altre;
applicare un alto livello di entropia nella generazione dell'OTP;
se l'utente preferisce ricevere una chiamata non lasciare l'OTP nella segreteria telefonica.

La crittografia asimmetrica è il miglior metodo per implementare firma delle transazioni.
L'app genera una coppia di chiavi quando l'utente accede e registra la chiave pubblica sul back end.
La chiave privata è memorizzata in modo sicuro nel KeyStore (Android) o nella KeyChain (iOS).
Per autorizzare una transazione, il back end invia una push notification contenente i dati della transazione.
L'utente conferma o nega la transazione.
Dopo la conferma, l'utente deve sbloccare la Keychain (inserendo un PIN o le impronte digitali), e i dati sono firmati con la chiave privata.
La transazione firmata è iniviata al server, che verifica la firma con la chiave pubblica dell'utente.

### Static Analysis

L'app può usare librerie di terze parti, app esterne o controlli implementati dagli sviluppatori.
Usa l'app e valuta dove è necessaria la 2FA.
Parla con gli sviluppatori e gli architect per capire l'implementazione.
Se viene usata una libreria di terze parti o un'app esterna, verifica se sono state seguite le best practice.

### Dynamic Analysis

Usa tutta l'app, catturando le richieste tramite un proxy.
Riesegui le richieste che richiedeono la 2FA usando un token o session id che non è stato ancora autorizzato tramite 2FA.
Se l'endpoint risponde allora i controlli di autenticazione non sono stati implementati adeguatamente.

Per verifacare la protezione da brute force contro l'OTP, invia più richieste con OTP casuali all'endpoint e infine quello corretto.
Se viene accettato l'implementazione è vulnerabile e bruteforce.
Il numero massimo di tentativi dovrebbe essere 3.

## Testing Stateless (Token-Based) Authentication (MSTG-AUTH-3)

L'autenticazione stateless viene implementata inviando un token firmata in ogni richiesta.
Il formato del token maggiormente utilizzato è il JSON Web Token (JWT).
Il singolo token può memorizzare lo stato completo della sessione evitando che il server lo mantenga.
Il JWT è composto da tre parti base64-encoded separate da punto:

- header: `{"alg":"HS256","typ":"JWT"}`, indica l'algoritmo di hashing e il tipo di token
- payload: `{"sub":"1234567890","name":"John Doe","admin":true}`, contiene i dati utili
- signature: `HMACSHA256(base64UrleEncode(header) + "." + base64UrlEncode(payload), secret)`, creata applicando l'algoritmo di hashing indicato nell'header sul payload encoded usando una chiave segreta

La chiave segreta è condivisa tra il server di backend e l'authentication server, infatti non è conosciuta dal client.
Questo permette di verificare che il token sia stato ottenuto da un servizio di autenticazione legittimo.
Ciò impedisce anche al client di modificare il contenuto del payload.

### Static Analysis

Identifica la libreria JWT usata lato client e lato server e verifica se ci sono vulnerabilità conosciute.
Verifica che l'implementazione aderisca alle best practice del JWT:

- HMAC è verificato per tutte le richieste contenenti un token
- verifica dove sono la chiave privata di firma o la chiave segreta HMAC.
Dovrebbero essere sul server e non dovrebbero mai essere condivise col client
- verifica che non ci siano informazioni sensibili nel payload del JWT
Se questi sono necessari, assicurati che siano cifrati.
- assicurati che i replay attack siano evitati utilizzando un JWT ID (`jti`)
- verifica che i token siano memorizzati in modo sicuro sul dispositivo (KeyStore o KeyChain)

L'implementazione deve imporre la verifica tramite firma, impedendo l'uso di 'none' come algoritmo di hashing.

Il JWT una volta firmato è valido per sempre.
Per limitarne la durata, controlla che ci sia un campo `exp` nel payload e che il backend non accetti token scaduti.
Di solito si usano due token: access token e refresh token.
Il primo di durata molto limitata rispetto al secondo.
Il secondo serve a ottenere il primo, ogni volta che il primo scade.

### Dynamic Analysis

Verifica le seguenti vulnerabilità sull'uso del JWT:

- individua la locazione di archiviazione sul dispositivo
- prova a fare il bruteforcing della chiave segreta tramite tool offline ( [jwtbrute](https://github.com/jmaxxz/jwtbrute), [crackjwt](https://github.com/Sjord/jwtcrack/blob/master/crackjwt.py))
- decodifica il payload e verifica se le informazioni presenti sono sensibili
- il server di backend può essere configurato per verificare la firma tramite chiavi asimmetriche, si aspetta quindi di ricevere un token firmato con la chiave privata e di verificarlo con la chiave pubblica.
Impostando nell'header l'algoritmo di hashing ad HMAC, il server potrebbe usare la chiave pubblica come chiave segreta per la verifica del token.
Verifica che questo non accada.
- verifica che il server non accetti token con algoritmo di hashing impostato a `none` e signature impostata a `""`

In BURP puoi usare i plugin `JSON Web Token Attacker` e `JSON Web Token`.

## Testing OAuth 2.0 Flows (MSTG-AUTH-1 and MSTG-AUTH-3)

OAuth 2.0 è principalmente usata per:
ottenere i permessi dall'utente per accedere a servizi online usando il suo account,
autenticarsi su un servizio online per conto dell'utente,
gestire gli errori di autenticazione.

I ruodi definiti da OAuth 2.0 sono:
resource owner (proprietario dell'account),
client (app che vuole accedere tramite l'account dell'utente con un access token),
resource server (server che ospita l'account dell'utente),
authorization server (verifica l'identità dell'utente ed emette gli access token per l'app).

1. l'app richiede l'autorizzazione all'utente per accedere alle risorse
2. l'app riceve un authorization grant
3. l'app presenta all'authorization server la sua identità e l'authorization grant
4. se l'identità dell'app è autenticata e l'authorization grant è valido, l'authorization server emette un access token per l'app; all'access token potrebbe essere accoppiato un refresh token
5. l'app usa l'authorization token per ottenere le risorse dal resource server
6. se l'authorization token è valido, il resource server fornisce la risorsa all'app

Verifica che le seguenti best practice siano rispettate:

- user agent:
l'utente dovrebbe aver modo di verificare la fiducia (conferma TLS);
il client dobrebbe validare il FQDN del server con la chiave pubblica quando stabilisce la connessione
- tipo di grant:
nelle app native dovrebbe essere usato il code grant invece dell'implicit grant;
quando usa il code grant, il PKCE dovrebbe essere implementato per proteggerlo, assicurarsi che anche il server lo implementi;
l'auth "code" dovrebbe avere vita breve ed essere usato subito dopo la ricezione, verificare che non venga loggato o memorizzato
- client secret:
gli shared secret non dovrebbero essere usati per provare l'identità del client dato che il client potrebbe essere impersonato;
se l'app usa i client secret assicurati che siano memorizzati in storage sicuro
- end user credential:
rendi sicura la trasmissione delle credenziali con metodi a livello di trasporto (es. TLS)
- token:
mantieni i token di accesso in RAM;
i token di accesso dovrebbero essere trasmessi su connessioni cifrate;
riduci lo scope e la durata dei token di accesso quando la confidenzialità end-to-end non può essere garantita o il token fornisce accesso a informazioni o transazioni sensibili;
ricorda che un attaccante che ha rubato un token ha accesso al suo scope e a tutte le risorse ad esso associate se l'app lo usa come mero token senza aver modo di identificare l'identità del client;
memorizza i refresh token in un secure local storage

L'autenticazione OAuth2 può essere eseguita sfruttando un user agent esterno (es. Chrome) o averla embedded nell'app stessa (es. libreria di autenticazione).
Nessuna delle due è migliore dell'altra, la scelta dipende dal contesto.
Si usa un user agent esterno quando l'app ha bisogno di interagire con gli account di social network.
In questo modo le credenziali dell'utente non sono mai esposte all'app.
Pochissimo codice di autenticazione va aggiunto all'app, riducendo così il rischio di errori.
Dall'altro lato non c'è possibilità di controllare il comportamento del browser (es. attivare il certificate pinning).
Per le app che operano all'interno di un ecosistema chiuso, l'autenticazione embedded è la scelta migliore.
Per applicazioni bancarie è meglio avere un processo di autenticazione interno piuttosto che basarsi su componenti esterni.

## Testing Login Activity and Device Blocking (MSTG-AUTH-11)

Per le app che richiedono protezione a livello 2, l'app informa l'utente di tutti i login col suo account.
Gli utenti hanno una lista di dispositivi usati per accedere, e possono bloccarne alcuni.
Questo può essere applicato in diversi modi:

- l'applicazione invia una push notification quando l'accont viene usato su un altro dispositivo per notificare all'utente le diverse attività;
l'utente può bloccare questo dispositivo dopo aver aperto l'app tramite la push notification
- se dopo il login la sessione precedente era su una configurazione diversa rispetto a quella attuale, all'utente vengono presentate le informazioni relative al login precedente.
L'utente può segnalare attività sospette e bloccare il dispositivo usato nella sessione precedente
- l'app mostra l'ultima sessione dopo ogni login
- l'app ha un portale in cui l'utente può gestire i diversi dispositivi tramite cui ha eseguito gli accessi

In tutti i casi, dovresti verificare se i diversi dispositivi sono identificati correttamente.
Quindi il collegamento tra l'app e il dispositivo effettivo dovrebbe essere testato.

Infine, il blocco dei dispositivi dovrebbe essere testato, bloccano un'istanza registrata dell'app e verificando se non è più consentito autenticarsi.
Se l'app richiede protezione a livello 2, può essere una buona idea avvertire l'utente anche prima dell'autenticazione su un nuovo dispositivo.
Invece avverti l'utente quando una seconda istanza dell'app viene registrata.

