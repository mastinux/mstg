# Testing Code Quality

## Injection Flaws (MSTG-ARCH-2 and MSTG-PLATFORM-2)

### SQL Injection

[OMITTED]

### XML Injection

Tra gli attacchi di XML Injection rientra l'attacco XML eXternal Entity (XXE).
Con quest'ultimo, l'attaccante può accedere a file locali, eseguire richieste HTTP verso host e porte arbitrari, lanciare un attacco CSRF e creare una condizione di DoS.

Il trend attuale privilegia l'uso di servizi basati su REST/JSON piuttosto che su XML.
Per i servizi che lo usano, è necessario fare validazione dell'input e fare l'escaping dei meta-character.

### Injection Attack Vectors

Gli attacchi di injection contro un'app si verificano molto spesso attraverso le interfacce di inter-process communication (IPC), tramite cui un'app malevola attacca un'altra app in esecuzione sul device.

L'individuazione di potenziali vulnerabilità inizia da:

- identificazione di possibili entry point per input non fidati al fine di determinare se le loro destinazioni contengono funzioni potenzialmente vulnerabili
- identificazione di librerie e API pericolose e verifica se l'input non controllato si interfaccia con le rispettive query

Durante una security review manuale, dovresti applicare entrambi i principi.
In generale, gli input non fidati entrano nella mobile app attraverso:
chiamate IPC, 
schema URL custom, 
QR code, 
file ricevuti tramite Bluetooth, NFC o altro, 
pasteboard, 
user interface.

Verifica che le seguenti best practice siano state seguite:

- gli input non fidati siano stati type-checked e/o validati usando una white list di valori accettabili
- siano usati i prepared statement con il binding delle variabili quando si eseguono query al database
- quando si fa il parsing di dati XML, assicurati che il parser dell'app sia configurato per impedire la risoluzione di entità esterne per evitare attacchi XXE
- quando si adoperano dati di un certificato formattato secondo x509, assicurati che sia usato un parser sicuro

## Cross-Site Scripting Flaws (MSTG-PLATFORM-2)

Nell'ambito delle app native, i rischi di XSS sono molto meno diffusi per la semplice ragione che queste app non si basano su un web browser.
Tuttavia le app che usano componenti WebView, come `WebView` in Android e `WKWebView` in iOS (o il deprecato `UIWebView` sempre in iOS) sono potenzialmente vulnerabili a tali attacchi.

### Static Analysis

Controlla qualsiasi WebView e verifica se l'input non fidato viene renderizzato dall'app (es. `webView.loadUrl()`).

Verifica che le seguenti best practice siano applicate:

- nessun dato non fidato viene renderizzato in HTML, JavaScript o altro contesto interpretato a meno che non sia assolutamente necessario
- viene applicato un appropriato encoding per fare l'escaping dei caratteri, come HTML entity encoding

### Dynamic Analysis

Per individuare vulnerabilità di reflected XSS puoi usare BURP Scanner.

## Memory Corruption Bugs (MSTG-CODE-8)

I bug di corruzione della memoria sono il risultato di errori di programmazione che portano il programma ad accedere a locazioni di memoria non volute.
Sotto le opportune condizioni, gli attaccanti possono sfruttare questo comportamento per modificare il flusso di esecuzione del programma vulnerabile ed eseguire codice arbitrario.
Questa vulnerabilità si verifica in diversi modi:

- buffer overflow:
errore di programmazione in cui l'app scrive oltre un range di memoria allocato per una particolare operazione.
Un attaccante può usare questa vulnerabilità per sovrascrivere dati di controllo importanti che si trovano nella memoria adiacente, come puntatori a funzione
- out-of-bound-access:
se l'aritmentica dei puntatori è errata potrebbe far puntare un puntatore o un indice oltre i limiti della struttura di memoria.
Quando un'app cerca di scrivere in un indirizzo al di fuori di questi limiti, si possono verificare crash o comporamenti non desiderati.
Se l'attaccante può controllare l'offset e manipolare i valori scritti, può realizzare una code execution
- dangling pinter:
si verifica quando un oggetto A referenziato da un oggetto B, viene eliminato o deallocato, ma il puntatore dall'oggetto B all'oggetto A non viene pulito.
Se il programma usa il dangling pointer per chiamare una funzione virtuale dall'oggetto B, è possibile dirottare l'esecuzione sovrascrivendo il puntatore originale della vtable.
Oppure, è possibile leggere o scrivere variabili o altre strutture di memoria referenziate da un dangling pointer
- use-after-free:
caso particolare di dangling pointer in cui si accede a memoria già rilasciata.
Quando un indirizzo di memoria viene rilasciato, tutti i puntatori che lo referenziano diventano invalidi, e il memory manager inserisce l'indirizzo nel pool di memoria disponibile.
Se questa locazione di memoria viene riallocata, l'accesso al puntatore originale farà leggere o scrivere i dati contenuti nella nuova memoria allocata.
Di solito questo porta a corruzione dei dati e comportamenti indesiderati, ma un attancante potrebbe preparare una locazione di memoria appropriata per controllare l'instruction pointer
- integer overflow:
quando il risultato di un'operazione aritmetica supera il massimo valore per il tipo integer definito dal programmatore, allora il valore viene "wrapped" intorno al massimo valore integer, risultando nella memorizzazione di un valore piccolo.
Dall'altro lato, quando il risultato di un'operazione aritmetica è più piccolo del valore minimo del tipo integer, si verifica un integer underflow per cui il risultato è più grande di quello che ci si aspetta.
La possibilità di sfruttare un integer overflow/underflow dipende dal modo in cui il risultato dell'operazione aritmetica viene usato
- format string vulnerability:
quando l'input non controllato dell'utente viene passato come parametro a una format string della famiglia di `printf` di C, l'attaccante potrebbe iniettare format token come %c e %n per accedere alla memoria.
L'attaccante potrebbe leggere e scrivere in modo arbitrario la memoria, aggirando le feautre di protezione come ASLR.

L'obiettivo primario nello sfruttamento della corruzione della memoria è di solito la redirezione del flusso del programma in una locazione in cui l'attaccante ha piazzato istruzioni macchina che prendono il nome di shellcode.
In iOS, la feature di data execution prevention impedisce l'esecuzione di codice a partire da segmenti marcati come dati.
Per aggirare questa feature, gli attaccanti sfruttano il return-oriented programming (ROP).
Con questo processo si concatenano piccoli pezzi di codice preesistenti in segmenti di testo in cui potrebbero eseguire una funzione utile all'attaccante o chiamare `mprotect` per chambiare le impostazioni di protezione della memoria per la locazione in cui l'attaccante ha piazzato lo shellcode.

Le app Android sono per la maggior parte implementate in Java, il che le protegge da bug legati a corruzione di memoria.
Tuttavia le app native che utilizzano librerie JNI sono suscettibili a questo tipo di bug.
Analogamente, le app iOS possono usare chiamate C/C++ in Obj-C o Swift, rendendole ugualmente suscettibili.

### Buffer and Integer Overflows

Per identificare eventuali buffer overflow, cerca funzioni insicure di manipolazione di stringhe: 
strcat, 
strcpy, 
strncat, 
strlcat, 
strncpy,
strlcpy
sprintf,
snprintf,
gets.
Inoltre, cerca istanze di operazioni di copia implementate in loop `for` o `while` e verifica che siano eseguiti correttamente i controlli sulle lunghezze.

Verifica che le seguenti best practices siano state applicate:

- quando si usano variabili integer per l'indexing di array, calcolo della lunghezza del buffer o altre operazioni critiche dal punto di vista della sicurezza, 
verifica che siano usati tipi unsigned integer
- l'app non usi funzioni insicure di manipolazione di stringhe
- se l'app contiene codice C++, verifica che siano usate le classi di stringhe ANSI C++
- in caso di `memcpy`, assicurati che il buffer di destinazione sia almeno grande quanto quello sorgente e che entrambi non si sovrappongano
- le app iOS scritte in Objective-C usino la classe NSString.
Le app iOS scritte in C dovrebbero usare CFString
- nessun dato non fidato venga concatenato in una format string

### Static Analysis

Individuare questi bug tramite analisi statica è molto difficile.

### Dynamic Analysis

I bug di corruzione di memoria vengono scoperti soprattutto tramite l'input fuzzing.
