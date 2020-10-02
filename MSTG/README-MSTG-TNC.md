# Testing Network Communication

Burp Suite, OWASP ZAP e Charles Proxy consentono di intercettare traffico HTTP(S).
Per intercettare traffico non HTTP puoi usare plugin di BURP come BURP-non-HTTP-Extension e Mitm-relay.

## Intercepting Traffic on the Network Layer

L'analisi dinamica tramite l'uso di un proxy può essere semplice se nell'app vengono usate librerie standard e tutte le comunicazioni sono eseguite tramite HTTP.
Ma in alcuni casi non è possibile:

- se vengono usate piattaforme di sviluppo di app mobile come Xamarin che ignora il proxy di sistema
- se l'app verifica l'utilizzo di un proxy e non invia le richieste attraverso esso
- se vuoi intercettare le push notification, come GCM/FCM su Android
- se vengono usati XMPP o altri protocolli non-HTTP

In questi casi è necessario prima monitorare e analizzare il traffico per decidere cosa fare dopo.
Esistono diverse opzioni:

- instradare il traffico attraverso la tua macchina.
Puoi impostare la tua macchina come gateway della rete e fare lo sniffing del traffico tramite Wireshark
- in alcuni casi è necessario eseguire un attacco MITM per forzare il device a parlare con la tua macchina.
È consigliabile usare bettercap per redirigere il traffico dal device al tuo host
- su device rooted puoi usare l'hooking o la code injection per intercettare le chiamate alle API e fare il dump o manipolare gli argomenti delle chiamate.
In questo modo non è necessario ispezionare il traffico di rete
- su macOS puoi creare una Remote Virtual Interface per fare lo sniffing di tutto il traffico di un dispositivo iOS

## Simulating a Man-in-the-Middle Attack

Puoi usare bettercap per simulare un attacco MITM durante un network penetration testing.
Per monitorare e analizzare il traffico puoi usare Wireshark e tcpdump.

## Span Port / Port Forwarding

In alternativa all'attacco MITM, puoi usare un Access Point o router WiFi sul quale è possibile abilitare il port forwarding o la span port.

## Setting a Proxy Through Runtime Instrumentation

Su un device rooted o jailbroken, puoi usare l'hooking a runtime per impostare un nuovo proxy o redirigere il traffico.
Puoi usare hooking tools come Inspeckage o framework di code injection come Frida o cycript.

## Verifying Data Encryption on the Network (MSTG-NETWORK-1 and MSTG-NETWORK-2)

### Static Analysis

Identifica tutte le richieste a servizi API/web nel codice sorgente e assicurati che non venga usata nessuna URL HTTP.
Assicurati che le informazioni sensibili siano inviate usando HttpsURLConnection o SSLSocket.
Ricorda che SSLSocket non verifica l'hostname.
Usa getDefaultHostnameVerifier() per verificare l'hostname.
Verifica che il server o il termination proxy su cui la connessione HTTPS termina sia configurata secondo le best practices.

### Dynamic Analysis

Intercetta il traffico dell'app e assicurati che sia cifrato.
Per verificare le cipher suite supportate dal sever puoi usare nscurl o testssl.sh.

## Making Sure that Critical Operations Use Secure Communication Channels (MSTG-NETWORK-5)

### Static Analysis

Analizza il codice e identifica le parti che fanno riferimento a operazioni critiche.
Assicurati che canali di verifica addizionale siano utilizzati per queste operazioni.
Esempi di canali di verifica addizionale possono essere:

- token
- push notification
- dati da un altro sito che l'utente ha visitato
- dati da una lettera fisica o un ente fisico

Assicurati che le operazioni critiche costringano all'uso di almeno un canale addizionale per confermare le azioni dell'utente.
Questi canali non devono essere aggirati quando vengono eseguite operazioni critiche.
Si consiglia l'uso di un'OTP tramite Google Authenticator.

### Dynamic Analysis

Identifica tutte le operazioni critiche (es. iscrizione dell'utente, recupero dell'account, transazioni finanziarie).
Assicurati che ogni operazione critica richieda almeno un canale di verifica addizionale.
Assicurati che la chiamata diretta alla funzione non possa aggirare l'uso di questi canali.
