# Tampering and Reverse Engineering on Android

L'apertura di Android lo rende un ambiente favorevole al reverse engineering.
In questo capitolo, analizzeremo alcune peculiarità dei tool di reversing in Android e dei tool specifici del SO.

Android offre ai reverse engineer grandi vantaggi che non sono disponibili in iOS.
Dato che Android è open source, puoi studiare il suo codice sorgente dall'Android Open Source Project (AOSP) e modificare il SO e i suoi tool standard in qualsiasi modo tu voglia.
Anche sui dispositivi standard è possibile attivare la developer mode e caricare app senza fare troppi salti mortali.
Dall'insieme di tool offerti dall'SDK all'ampia gamma di tool di reverse engineering, ci sono diverse minuzie che possono facilitarti il lavoro.

Tuttavia, ci sono anche alcune sfide Android.
Per esempio, dovrai avere a che fare sia con il Java byte-code che con codice nativo.
Java Native Interface (JNI) a volte è usato per confondere i reverse engineer (ci sono ragioni legittime per usare JNI, come il miglioramento delle performance o il supporto di codice legacy).
A volte gli sviluppatori usano il layer nativo per "nascondere" i dati e le funzionalità, e potrebbero strutturare le loro app in modo che l'esecuzione salti frequentemente tra i due layer.

Avrai bisogno di almeno una conoscenza base dell'ambiente Android basato su Java e del SO e Kernel Linux, su cui Android è basato.
Avrai bisogno anche dei tool giusti per gestire il bytecode in esecuzione su una JVM e il codice nativo.

Useremo gli OWASP Mobile Security Testing Guide Crackmes come esempi per dimostrare diverse tecniche di reverse engineering nelle sezioni successive, quindi aspettati spoiler parziali o totali.
Ti raccomandiamo di provarci prima da solo e poi continuare a leggere.

### Reverse Engineering

Il reverse engineering consiste nello smontare un'app e capire come funziona.
Puoi farlo esaminando l'app compilata (analisi statica), osservando l'app a run time (analisi dinamica), o entrambe.

### Tooling

Assicurati che i seguenti tool siano installati sul tuo sistema (vedi il capitolo "Android Basic Security Testing" per l'installazione):

- gli ultimi tool SDK e platform-tool SDK.
Questi pacchetti includono il client Android Debug Bridge (ADB) e altri tool che si interfacciano con la piattaforma Android
- l'Android NDK.
La Native Development Kit contiene toolchain precompilate per cross-compile di codice nativo per diverse architetture.
Ne avrai bisogno se pensi di dover trattare codice nativo, es. per ispezionarlo o per debug (la NDK contiene versioni precompilate utili come gdbserver o strace per diverse architetture)

Inoltre, avrai bisogno di qualcosa per rendere il Java bytecode più human-readable.
Fortunatamente, i decompiler Java gestiscono bene il bytecode Android.
JD, JAD, Procyon e CFR sono famosi decompiler gratuiti.
Puoi usare lo script [apkx](https://github.com/b-mueller/apkx) che racchiude alcuni di questi decompiler.
Questo script automatizza completamente il processo di estrazione del codice Java dai file APK di release.

Altri tool sono scelti in base a preferenze e budget.
Esistono molti disassembler, decompiler e framework gratuiti e commerciali con punti di forza e di debolezza diversi.
Li vedremo in questo capitolo.

#### Building a Reverse Engineering Environment for Free

Con un piccolo sforzo, puoi creare un ambiente di reverse engineering GUI-based ragionevole in modo gratuito.

Per la navigazione dei sorgenti decompilati, raccomandiamo IntelliJ, un IDE relativamente leggero e ottimo per la navigazione del codice.
Consente debugging su device di base per app decompilate.
Tuttavia, se preferisci qualcosa che sia goffo, lento e complicato da usare, Eclipse è l'IDE giusto per te (secondo il pregiudizio personale dell'autore).

Se non ti cambia analizzare Smali invece che Java, puoi usare il plugin di IntelliJ smalidea per il debugging.
Smalidea supporta il single-stepping attraverso il bytecode e il renaming degli identificatori, e monitora i registri senza nome, che lo rendono più potente del setup JD + IntelliJ.

apktool è un tool famoso gratuito che può estrarre e disassemblare risorse direttamente dall'APK e disassemblare bytecode Java nel formato Smali 
(Smali/Backsmali è un assembler/disassembler per il formato Dex. 
È Assembler/Disassembler in islandese).
apktool ti permette di riassemblare il package, che risulta utile per il patching e per l'applicazione di modifiche all'Android Manifest.

Puoi eseguire compiti più elaborati (come l'analisi del programma e il deoffuscamento automatico) con framework di reverse engineering gratuiti come Radare2 e Angr.
Troverai diversi esempi per molti di questi tool e framework gratuiti in questa guida.

#### Commercial Tools

È possibile preparare un ambiente di reverse engineering gratuitamente.
Tuttavia, esistono delle alternative commerciali.
Quelle maggiormente usate sono:

- JEB,
un decompiler commerciale,
impacchetta tutte le funzionalità necessarie all'analisi statica e dinamica delle app Android in un solo package.
È ragionevolmente affidabile e include un supporto al prompt.
Ha un debugger built-in, che consente l'inserimento di breakpoint direttamente nei sorgenti decompilati (e annotati), specialmente nel codice offuscato con Proguard.
Ovviamente, questa comodità non è gratis, e ora che JEB ha una licenza subscription-based, richiede un canone mensile
- IDA Pro nella sua versione a pagamento è compatibile con ARM, MIPS, bytecode Java, e, ovviamente, binary ELF.
Ha un debugger sia per applicazioni Java che per processi nativi.
Con i suoi potenti scripting, disassembling ed estensioni, IDA Pro funziona benissimo per l'analisi statica di programmi nativi e librerie.
Tuttavia, le capacità di analisi statica offerte per Java sono molto base: ottieni l'assembly Smali ma niente di più.
Non puoi navigare nel package e nella struttura delle classi, e alcune azioni (come il renaming delle classi) non possono essere eseguite, che per alcune app più complesse potrebbe essere noioso.
Inoltre, a meno che tu non possa avere la versione a pagamento, non sarà d'aiuto durante il reverse engineering di codice nativo dato che la versione freeware non supporta i processori ARM.

### Disassembling and Decompiling

Nel security testing di app Android, se l'app è basata solo su Java e non ha alcun codice nativo (codice C/C++), il processo di reverse engineering è relativamente facile e recupera (decompila) quasi tutto il codice sorgente.
In questi casi, il black-box testing (con l'accesso al binario compilato, ma non al codice sorgente originale) può essere molto vicino al white-box testing.

Tuttavia, se il codice è stato appositamente offuscato (o sono stati usati tool di anti decompilazione), il processo di reverse engineering potrebbe essere molto dispendioso e improduttivo.
Ciò riguarda anche le applicazioni che contengono codice nativo.
Si può applicare il reverse engineering, ma il processo non è automatizzato e richiede la conoscenza di dettagli di basso livello.

#### Decompiling Java Code

Il processo di decompilazione consiste nel convertire il bytecode Java in codice sorgente Java.
Useremo l'app UcCrackable per Android Level 1 nei seguenti esempi.

```sh
$ wget https://github.com/OWASP/owasp-mstg/raw/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk
$ adb install UnCrackable-Level1.apk
```

Usando l'app vediamo che richiede un secret.
Lo cerchiamo nell'apk.

```sh
$ unzip UnCrackable-Level1.apk -d UnCrackable-Level1
```

Nel setup standard, tutto il bytecode Java e i dati dell'app sono nel file `classes.dex` nella root directory dell'app.
Questo file è conforme al Dalvik Executable Format (DEX), una specifica Android per il packaging di programmi Java.
Molti decompiler Java usano file di classi o JAR come input, quindi devi prima convertire il file classes.dex in un file JAR.
Puoi usare `dex2jar` o `enjarify`.

Quando hai il file JAR, puoi usare un qualsiasi decompiler per produrre codice JAVA.
In questo esempio useremo il decompiler CFR.
CFR è in sviluppo attivo, e nuove release sono disponibili sul sito degli autori.
CFR è rilasciato sotto licenza MIT, quindi puoi usarlo liberamente anche se il suo codice sorgente non è disponibile.

Il modo più semplice per eseguire CFR è attraverso `apkx`, che include anche `dex2jar` e automatizza l'estrazione, la conversione e la decompilazione.

```sh
$ git clone https://github.com/b-mueller/apkx
$ cd apkx
$ sudo ./install.sh
```

Dovrebbe copiare `apkx` in `/usr/local/bin`.
Eseguilo passando `UnCrackable-Level1.apk`.

```sh
$ apkx UnCrackable-Level1.apk
Extracting UnCrackable-Level1.apk to UnCrackable-Level1
Converting: classes.dex -> classes.jar (dex2jar)
dex2jar UnCrackable-Level1/classes.dex -> UnCrackable-Level1/classes.jar
Decompiling to UnCrackable-Level1/src (cfr)
```

Dovresti trovare i sorgenti decompilati nella directory `UnCrackable-Level1/src`.
Per vedere i sorgenti, un semplice text editor (preferibilimente con syntax highlight) è accettabile, ma il caricamento del codice in un IDE Java rende la navigazione più facile.
Importiamo il codice in IntelliJ, che fornisce anche una funzionalità di debugging su device.

Apri IntelliJ e scegli "Android" come tipo di progetto nel tab di sinistra nel dialog "New Project".
Inserisci "Uncrackable1" come nome dell'app e "vantagepoint.sg" come company name.
Risulta la creazione del package "sg.vantagepoint.uncrakable1", che corrisponde al nome originale del package.
L'usod di un nome uguale è importante se vuoi agganciare il debugger all'app in esecuzione dato che IntelliJ usa il package name per identificare il processo corretto.

Nel dialog successivo, scegli un qualsiasi API number, non compilerai realmente il progetto, quindi il numero non conta.
Scegli "next" e "Add no Activity", poi clicca su "finish".

Una volta creato il progetto, espandi la vista "1: Project" sulla sinistra e naviga nel folder `app/src/main/java`.
Tasto destro ed elimina il package di default `sg.vantagepoint.uncrackable1` creato da IntelliJ.

Ora, apri la directory `Uncrackable-Level1/src` in un file browser e copia la directory `sg` nel folder `Java` ora vuoto nella vista del progetto IntelliJ.

Otterrai una struttura che somiglia al progetto Android Studio a partire dal quale l'app è stata creata.

Guarda la sezione "Reviewing Decompiled Java Code" qui sotto per imparare a ispezionare il codice Java decompilato.

257

RILEGGI E PROVA COMANDI

#### Disassembling Native Code
