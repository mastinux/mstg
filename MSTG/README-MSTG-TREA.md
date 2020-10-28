# Tampering and Reverse Engineering on Android

L'apertura di Android lo rende un ambiente favorevole al reverse engineering.
In questo capitolo, analizzeremo alcune peculiarità dei tool di reversing in Android e dei tool specifici del SO.

Android offre ai reverse engineer grandi vantaggi che non sono disponibili in iOS.
Dato che Android è open source, puoi studiare il suo codice sorgente dall'Android Open Source Project (AOSP) e modificare il SO e i suoi tool standard in qualsiasi modo tu voglia.
Anche sui dispositivi standard è possibile attivare la developer mode e caricare app senza fare troppi salti mortali.
Dall'insieme di tool offerti dall'SDK all'ampia gamma di tool di reverse engineering, ci sono diverse minuzie che possono facilitarti il lavoro.

Tuttavia, ci sono anche alcune sfide Android.
Per esempio, dovrai avere a che fare sia con il Java byte-code che con il codice nativo.
La Java Native Interface (JNI) a volte è usata per confondere i reverse engineer (ci sono ragioni legittime per usare JNI, come il miglioramento delle performance o il supporto di codice legacy).
A volte gli sviluppatori usano il layer nativo per "nascondere" i dati e le funzionalità, e potrebbero strutturare le loro app in modo che l'esecuzione salti frequentemente tra i due layer.

Avrai bisogno di almeno una conoscenza base dell'ambiente Android basato su Java e del SO e Kernel Linux, su cui Android è basato.
Avrai bisogno anche dei tool giusti per gestire il bytecode in esecuzione su una JVM e il codice nativo.

Useremo gli OWASP Mobile Security Testing Guide Crackmes come esempi per dimostrare diverse tecniche di reverse engineering nelle sezioni successive, quindi aspettati spoiler parziali o totali.
Ti raccomandiamo di provarci prima da solo e poi continuare a leggere.

### Reverse Engineering

Il reverse engineering consiste nello smontare un'app e capire come funziona.
Puoi farlo 
esaminando l'app compilata (analisi statica), 
osservando l'app a run time (analisi dinamica), o 
entrambe.

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
Puoi usare lo script [apkx](https://github.com/b-mueller/apkx) che incrorpora alcuni di questi decompiler.
Questo script automatizza completamente il processo di estrazione del codice Java dai file APK.

Altri tool sono scelti in base a preferenze e budget.
Esistono molti disassembler, decompiler e framework gratuiti e commerciali con punti di forza e di debolezza diversi.
Li vedremo in questo capitolo.

#### Building a Reverse Engineering Environment for Free

Con un piccolo sforzo, puoi creare un buon ambiente di reverse engineering GUI-based gratuitamente.

Per la navigazione dei sorgenti decompilati, raccomandiamo IntelliJ, un IDE relativamente leggero e ottimo per la navigazione del codice.
Consente debugging su device di base per app decompilate.
Tuttavia, se preferisci qualcosa che sia goffo, lento e complicato da usare, Eclipse è l'IDE giusto per te (secondo il pregiudizio personale dell'autore).

Se non ti cambia analizzare Smali invece che Java, puoi usare il plugin di IntelliJ `smalidea` per il debugging.
Smalidea supporta il single-stepping attraverso il bytecode e il renaming degli identificatori, e monitora i registri senza nome, che lo rendono più potente del setup JD + IntelliJ.

apktool è un tool gratuito famoso che può estrarre e disassemblare risorse direttamente dall'APK e disassemblare bytecode Java nel formato Smali 
(Smali/Backsmali è un assembler/disassembler per il formato Dex. 
In islandese è Assembler/Disassembler).
apktool ti permette di riassemblare il package, che risulta utile per il patching e per l'applicazione di modifiche all'Android Manifest.

Puoi eseguire compiti più complessi (come l'analisi del programma e il deoffuscamento automatico) con framework di reverse engineering gratuiti come Radare2 e Angr.
Troverai diversi esempi per molti di questi tool e framework gratuiti in questa guida.

#### Commercial Tools

È possibile preparare un ambiente di reverse engineering gratuitamente.
Tuttavia, esistono delle alternative commerciali.
Quelle maggiormente usate sono:

- JEB,
un decompiler commerciale,
impacchetta tutte le funzionalità necessarie all'analisi statica e dinamica delle app Android in un solo package.
È ragionevolmente affidabile e include un supporto per il prompt.
Ha un debugger built-in, che consente l'inserimento di breakpoint direttamente nei sorgenti decompilati (e annotati), specialmente nel codice offuscato con Proguard.
Ovviamente, questa comodità non è gratis, e ora che JEB ha una licenza subscription-based, richiede un canone mensile
- IDA Pro nella sua versione a pagamento è compatibile con ARM, MIPS, bytecode Java, e, ovviamente, binari ELF.
Ha un debugger sia per applicazioni Java che per processi nativi.
Con i suoi potenti script, disassembler ed estensioni, IDA Pro funziona benissimo per l'analisi statica di programmi nativi e librerie.
Tuttavia, le capacità di analisi statica offerte per Java sono molto base: ottieni l'assembly Smali ma niente di più.
Non puoi navigare nel package e nella struttura delle classi, e alcune azioni (come il renaming delle classi) non possono essere eseguite, che per alcune app più complesse potrebbe essere fastidioso.
Inoltre, a meno che tu non possa avere la versione a pagamento, non sarà d'aiuto durante il reverse engineering di codice nativo dato che la versione freeware non supporta i processori ARM.

### Disassembling and Decompiling

Nel security testing di app Android, se l'app è basata solo su Java e non ha alcun codice nativo (codice C/C++), il processo di reverse engineering è relativamente facile e recupera (decompila) quasi tutto il codice sorgente.
In questi casi, il black-box testing (con l'accesso al binario compilato, ma non al codice sorgente originale) può essere molto vicino al white-box testing.

Tuttavia, se il codice è stato appositamente offuscato (o sono stati usati tool di anti decompilazione), il processo di reverse engineering potrebbe essere molto dispendioso e improduttivo.
Ciò riguarda anche le applicazioni che contengono codice nativo.
Si può applicare il reverse engineering, ma il processo non è automatizzato e richiede la conoscenza di dettagli di basso livello.

#### Decompiling Java Code

Il processo di decompilazione consiste nel convertire il bytecode Java in codice sorgente Java.
Useremo l'app UnCrackable Level 1 per Android nei seguenti esempi.

```sh
$ wget https://github.com/OWASP/owasp-mstg/raw/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk
$ adb install UnCrackable-Level1.apk
```

Usando l'app vediamo che richiede un secret.
Lo cerchiamo nell'apk estraendone i file.

```sh
$ unzip UnCrackable-Level1.apk -d UnCrackable-Level1
```

Nel setup standard, tutto il bytecode Java e i dati dell'app sono nel file `classes.dex` nella root directory dell'app.
Questo file è conforme al Dalvik Executable Format (DEX), una specifica Android per il packaging di programmi Java.
Molti decompiler Java usano le classi o i JAR come input, quindi devi prima convertire il file classes.dex in un file JAR.
Puoi usare `dex2jar` o `enjarify`.

Quando hai il file JAR, puoi usare un qualsiasi decompiler per recuperare il codice Java.
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
L'uso di un nome uguale è importante se vuoi agganciare il debugger all'app in esecuzione dato che IntelliJ usa il package name per identificare il processo corretto.

Nel dialog successivo, scegli un qualsiasi API number, non compilerai realmente il progetto, quindi il numero non conta.
Scegli "next" e "Add no Activity", poi clicca su "finish".

Una volta creato il progetto, espandi la vista "1: Project" sulla sinistra e naviga nel folder `app/src/main/java`.
Tasto destro ed elimina il package di default `sg.vantagepoint.uncrackable1` creato da IntelliJ.

Ora, apri la directory `Uncrackable-Level1/src` in un file browser e copia la directory `sg` nel folder `java` ora vuoto nella vista del progetto IntelliJ.

Otterrai una struttura che somiglia al progetto Android Studio a partire dal quale l'app è stata creata.

Guarda la sezione "Reviewing Decompiled Java Code" qui sotto per imparare a ispezionare il codice Java decompilato.

#### Disassembling Native Code

Sia Dalvik che ART supportano la JNI, che definisce il modo con cui il codice Java interagisce con il codice nativo scritto in C/C++.
Come in altri SO Linux-based, il codice nativo viene impacchettato (compilato) in librerie dinamiche ELF (.so), che l'app Android carica a run time tramite il metodo `System.load`.
Tuttavia, invece di basarsi su librerie C diffuse (come glibc), i binari Android sono compilati rispetto a una libc custom chiamata Bionic.
Bionic aggiunge un supporto per servizi specifici di Android come system properties e logging, e non è completamente compatibile con POSIX.

Quando fai il reversing di app Android contenenti codice nativo dovrai considerare questo particolare layer tra Java e la JNI.
Vale la pena notare che quando si fa il reversing si ha bisogno di un disassembler.
Una volta che il binario sarà caricato, analizzerai il disassembly, che non è così facile da ispezionare come il codice Java.

Nell'esempio seguente faremo il reversing di HelloWorld-JNI.apk dal repository MSTG di OWASP.
L'installazione e l'esecuzione su emaulatore o device Android è opzionale.

```sh
wget https://github.com/OWASP/owasp-mstg/raw/master/Samples/Android/01_HelloWorld-JNI/HelloWord-JNI.apk
```

Quest'app non è un gran chè, tutto ciò che fa è mostrare una label con testo "Hello from C++".
Questa è l'app Android generata di default quando si crea un nuovo progetto con il supporto C/C++.
É sufficiente a mostrare i principi base delle chiamate JNI.

Decompila l'apk usando `apkx`.

```sh
$ apkx HelloWord-JNI.apk
Extracting HelloWord-JNI.apk to HelloWord-JNI
Converting: classes.dex -> classes.jar (dex2jar)
dex2jar HelloWord-JNI/classes.dex -> HelloWord-JNI/classes.jar
Decompiling to HelloWord-JNI/src (cfr)
```

Il codice viene estratto nella directory `HelloWorld-JNI/src`.
La main activity è nel file `HelloWord-JNI/src/sg/vantagepoint/helloworldjni/MainActivity.java`.

```java
public class MainActivity extends AppCompatActivity {
	static {
		System.loadLibrary("native-lib");
	}

	@Override
	protected void onCreate(Bundle bundle) {
		super.onCreate(bundle);
		this.setContentView(2130968603);

		((TextView)this.findViewById(2131427422))
			.setText((CharSequence)this.stringFromJNI());
	}

	public native String stringFromJNI();
}
```

Nota la dichiarazione di `public native String stringFromJNI`.
La keyword `native` dice al compiler Java che questo metodo è implementato in un linguaggio nativo.
La funzione corrispondente è risolta a run time, ma solo se viene caricata la libreria nativa che esporta un simbolo globale con la signature che si aspetta (la signature comprende nome di package, classe, metodo).
In questo esempio, questo requisito viene soddisfatto dalla seguente funzione C o C++:

```java
JNIEXPORT jstring JNICALL Java_sg_vantagepoint_helloworld_MainActivity_stringFromJNI(JNIEnv *env, jobject)
```

Per trovare l'implementazione nativa della funzione, cerca nella directory `lib` nell'apk.
In essa troverai otto sotto directory ognuna col nome di un'architettura di processore diversa.
Ognuna di queste contiene una versione della libreria nativa `libnative-lib.so` che è stata compilata per l'architettura del processore in questione.
Quando viene invocata `System.loadLibrary`, il loader sceglie la versione corretta in base al device su cui l'app è in esecuzione.

Secondo la naming convention menzionata prima, puoi aspettarti che la libreria esporti un simbolo chiamato `Java_sg_vantagepoint_helloworld_MainActivity_stringFromJNI`.
Sui sistemi Linux, puoi recuperare questa lista di simboli usando `readelf` (incluso nei binutils di GNU) o `nm`.
Su Mac OS usa `greadelf`, che puoi installare tramite Macports o Homebrew.

```sh
$ greadelf -W -s libnative-lib.so | grep Java
	3: 00004e49 112 FUNC GLOBAL DEFAULT 11 Java_sg_vantagepoint_helloworld_MainActivity_stringFromJNI
```

Puoi ottenere un output simile usando rabin2 di radare2:

```sh
$ rabin2 -s HelloWord-JNI/lib/armeabi-v7a/libnative-lib.so | grep -i Java
003 0x00000e78 0x00000e78 GLOBAL FUNC 16 Java_sg_vantagepoint_helloworldjni_MainActivity_stringFromJNI
```

Questa è la funzione nativa che verrà eseguita quando il metodo nativo `stringFromJNI` viene invocato.

Per disassemblare il codice, puoi caricare `libnative-lib.so` in un qualsiasi disassembler che supporta i binari ELF.
Se l'app contiene i binari di diverse architetture, puoi scegliere l'architettura con cui sei più pratico, quando questa è compatibile col disassembler.
Ogni versione è compilata dallo stesso sorgente e implementa la stessa funzionalità.
Tuttavia, se hai intenzione di fare il debug della libreria su un device, è di solito saggio scegliere la build per ARM.

Per supportare sia i vecchi che i nuovi processori ARM, le app Android hanno più build ARM compilate per diverse versioni di Application Binary Interface (ABI).
L'ABI definisce come il machine code dell'app interagisca con il sistema a run time.
Sono supportate le seguenti ABI:

- armeabi: 
per CPU ARM-based che supportano almeno l'instruction set AMRv5TE
- armeabi-v7a:
estende armeabi per includere diverse estensioni di instruction set
- arm64-v8a:
per CPU ARMv8-based che supporatno AArch64, la nuova archietettura ARM a 64 bit

Molti disassembler supportano tutte queste architetture.
Di seguito, vedremo la versione armeabi-b7a (in `HelloWord-JNI/lib/armeabi-v7a/libnative-lib.so`) in radare2 e in IDA Pro.
Guarda la sezione "Reviewing Disassembled Native Code" per imparare a ispezionare il codice nativo disassemblato.

##### radare2

Per aprire un file in radare2 devi eseguire solo `radare2 -A HelloWorld-JNI/lib/armeabi-v7a/libnative-lib.so`.
Il capitolo "Android Basic Security Testing" introduce già radare2.
Ricorda che puoi usare il flag `-A` per eseguire il comando `aaa` subito dopo aver caricato il binario per analizzare tutto il codice referenziato.

```sh
$ radare2 -A HelloWord-JNI/lib/armeabi-v7a/libnative-lib.so
Cannot determine entrypoint, using 0x00000e3c.
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
Warning: aao experimental on 32bit binaries
[x] Check for vtables
[x] Finding xrefs in noncode section with anal.in=io.maps
[x] Analyze value pointers (aav)
[x] Value from 0x00000000 to 0x00001dcf (aav)
[x] 0x00000000-0x00001dcf in 0x0-0x1dcf (aav)
[x] Emulate code to find computed references (aae)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
 -- Use the '[' and ']' keys in visual mode to adjust the screen width
[0x00000e3c]>
```

Nota che per binario più grandi, lanciare il comando direttamente col flag `-A` potrebbe rallentare molto l'esecuzione e potrebbe essere non necessario.
In base al tuo obiettivo, potresti aprire il binario senza quest'opzione e applicare un'analisi meno complessa come `aa` o un'analisi più concreta come quella offerta da `aa` (analisi base per tutte le funzioni) o `aac` (analisi per le chiamate a funzione).
Ricorda di digitare sempre `?` per visualizzare l'help o concatenalo a un comando per visualizzare più comando o opzioni.
Per esempio, se digiti `aa?` vedrai la lista completa di comandi di analisi.

```sh
[0x00000e3c]> aa?
Usage: aa[0*?]   # see also 'af' and 'afna'
| aa                  alias for 'af@@ sym.*;af@entry0;afva'
| aaa[?]              autoname functions after aa (see afna)
| aab                 abb across bin.sections.rx
| aac [len]           analyze function calls (af @@ `pi len~call[1]`)
| aac* [len]          flag function calls without performing a complete analysis
| aad [len]           analyze data references to code
| aae [len] ([addr])  analyze references with ESIL (optionally to address)
| aaf[e|r|t]          analyze all functions (e anal.hasnext=1;afr @@c:isq) (aafe=aef@@f)
| aaF [sym*]          set anal.in=block for all the spaces between flags matching glob
| aaFa [sym*]         same as aaF but uses af/a2f instead of af+/afb+ (slower but more accurate)
| aai[j]              show info of all analysis parameters
| aan[gr?]            autoname functions (aang = golang, aanr = noreturn propagation)
| aao                 analyze all objc references
| aap                 find and analyze function preludes
| aar[?] [len]        analyze len bytes of instructions for references
| aas [len]           analyze symbols (af @@= `isq~[0]`)
| aaS                 analyze all flags starting with sym. (af @@ sym.*)
| aat [fcn]           Analyze all/given function to convert immediate to linked structure offsets (see tl?)
| aaT [len]           analyze code after trap-sleds
| aau [len]           list mem areas (larger than len bytes) not covered by functions
| aav [sat]           find values referencing a specific section or map
[0x00000e3c]>
```

Vale la pena notare una differenza tra radare2 rispetto ad altri disassembler come IDA Pro.
Il seguente estratto da un articolo dal blog di radare2 esprime questa differenza.

> Code analysis is not a quick operation, and not even predictable or taking a linear time to be processed. 
> This makes starting times pretty heavy, compared to just loading the headers and strings information like it’s done by default.
> People that are used to IDA or Hopper just load the binary, go out to make a coffee and then when the analysis is done, they start doing the manual analysis to understand what the program is doing. 
> It's true that those tools perform the analysis in background, and the GUI is not blocked.
> But this takes a lot of CPU time, and r2 aims to run in many more platforms than just high-end desktop computers.

Detto ciò, guarda la sezione "Reviewing Disassembled Native Code" per capire come radare2 può aiutarci a fare il reversing più velocemente.
Per esempio, l'estrazione del disassembly di una funzione specifica è un task banale che può essere eseguito con un unico comando.

##### IDA Pro

Se hai una licenza IDA Pro, apri il file e quando appare il dialog "Load new file", scegli come tipo di file "ELF for ARM (Shared Object)" (IDA dovrebbe rilevarlo automaticamente) e come tipo di processore (ARM Little-Endian).

La versione freeware di IDA Pro sfortunatamente non suppoorta il tipo di processore ARM.

### Static Analysis

Per il white-box testing di codice sorgente, avrai bisogno di un setup simile a quello dello sviluppatore, incluso un test environment che includa l'Android SDK e un IDE.
Si raccomanda l'accesso a un device fisico o emulato (al fine di fare il debugging dell'app).

Durante il testing black-box, non avrai accesso alla forma originale del codice sorgente.
Avrai a disposizione l'apk dell'app, che può essere installata sul device Android o essere reversed come spiegato nella sezione "Disassembling and Decompiling".

## Manual (Reversed) Code Review

### Reviewing Decompiled Java Code

A seguito di "Decompiling Java Code", assumiamo tu abbia decompilato e aperto l'app crackme in IntelliJ.
Non appena IntelliJ ha indicizzato il codice, puoi navigarlo come se stessi navigando in un progetto Java.
Nota che molti dei pacchetti, classi e metodi decompilati hanno nomi con una singola lettera; questo è causato dal fatto che il bytecode è stato minified con ProGuard durante la build dell'apk.
Questo è un tipo di offuscamento base che rende il bytecode un po' più difficile da leggere, ma con un'app semplice come questa non avrai tanti problemi.
Quando analizzerai un'app più complessa, potrebbe diventare più difficile.

Quando si analizza il codice offuscato, è buona pratica annotare i nomi delle classi, i nomi dei metodi e altri identificatori che individui scorrendo il codice.
Apri la classe `MainActivity` nel package `sg.vantagepoint.uncrackable1`.
Il metodo `verify` viene invocato quando tocchi il button "verify".
Questo metodo passa l'imput utente al metodo statico `a.a`, che ritorna un valore booleano.
Sembra plausibile che il metodo `a.a` verifichi l'input utente, quindi modificheremo il codice per applicare questo fatto.

```java
public void verify(View view) {
	String str;
	String obj = ((EditText) findViewById(R.id.edit_text)).getText().toString();
	AlertDialog create = new AlertDialog.Builder(this).create();

	if (a.a(obj)) {
		create.setTitle("Success!");
		str = "This is the correct secret.";
	} else {
		create.setTitle("Nope...");
		str = "That's not it. Try again.";
	}

	create.setMessage(str);

	create.setButton(-3, "OK", new DialogInterface.OnClickListener() {
		public void onClick(DialogInterface dialogInterface, int i) {
			dialogInterface.dismiss();
		}
	});

	create.show();
}
```

Click destro sul nome della classe (la prima `a` in `a.a`) e scegli `Refactor` -> `Rename` dal menu (o premi Shift-F6).
Cambia il nome della classe con qualcosa che ha senso in base a quello che la classe fa.
Per esempio, potresti chiamarla `Validator` (puoi cambiare il nome anche successivamente).
`a.a` diventa `Validator.a`.
Segui la stessa procedura per rinominare il metodo statico `a` in `check_input`.

Congratulazioni, hai imparato i fondamenti dell'analisi statica!
Consiste tutto nel formulare una teoria, annotare e validare le teorie gradualmente fino a che si comprende completamente o almeno si capisce abbastanza per quello che è il proprio obiettivo.

Successivamente, fai Ctrl+click sul metodo `check_input`.
In questo modo IntelliJ ti porta alla definizione del metodo.
Il metodo decompilato assomiglia al seguente codice:

```java
public static boolean check_input(String str) {
	byte[] bArr;
	byte[] bArr2 = new byte[0];

	try {

		bArr = sg.vantagepoint.a.a.a(
			b("8d127684cbc37c17616d806cf50473cc"), 
			Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));

	} catch (Exception e) {
		Log.d("CodeCheck", "AES error:" + e.getMessage());
		bArr = bArr2;
	}

	return str.equals(new String(bArr));
}
```

In pratica, c'è una String Base64-encoded che viene passata alla funzione `a` nel package `sg.vantagepoint.a.a` (di nuovo, tutto viene chiamato `a`) insieme a qualcosa che sembra una chiave di cifratura in esadecimale (16 byte esadecimali = 128 bit, una comune lunghezza di chiave).
Cosa fa in particolare questa `a`?
Fai Ctrl+click per scoprirlo.

```java
public static byte[] a(byte[] bArr, byte[] bArr2) {
	SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES/ECB/PKCS7Padding");
	Cipher instance = Cipher.getInstance("AES");
	
	instance.init(2, secretKeySpec);

	return instance.doFinal(bArr2);
}
```

Sei arrivato a un buon punto: è un semplice AES-ECB.
Sembra che la String Base64 presente in `check_input` sia il ciphertext.
Viene decifrato con AES a 128 bit, poi confrontato con l'input utente.
Prova a decifrare il ciphertext estratto e trova il valore segreto.

Un modo più veloce per ottenere il valore decifrato è usare l'analisi dinamica.
Rivedremo l'app UnCrackable Level1 più avanti per mostrare come (es. nella sezione Debugging).

### Reviewing Disassembled Native Code

Continuando sull'esempio di "Disassembling Native Code" useremo diversi disassembler per analizzare il codice nativo disassemblato.

#### radare2

Una volta che hai aperto il file in radare2 dovresti recuperare l'indirizzo della funzione che stai cercando.
Puoi ottenere informazioni `i` sui simboli `s` (`is`) e facendo il grep (`~` è il grep built-in di radare2) di alcune parole chiave, nel nostro caso stiamo cercando i simboli relativi a JNI quindi cerchiamo "Java":

```sh
$ radare2 -A HelloWord-JNI/lib/armeabi-v7a/libnative-lib.so
...
[0x00000e3c]> is~Java
3    0x00000e78 0x00000e78 GLOBAL FUNC   16       Java_sg_vantagepoint_helloworldjni_MainActivity_stringFromJNI
```

Il metodo può essere trovato all'indirizzo `0x00000e78`.
Per vedere il suo disassembly esegui i seguenti comandi:

```sh
[0x00000e3c]> e emu.str=true;
[0x00000e3c]> s 0x00000e78
[0x00000e78]> af
[0x00000e78]> pdf
/ 12: sym.Java_sg_vantagepoint_helloworldjni_MainActivity_stringFromJNI (int16_t arg1);
|           ; arg int16_t arg1 @ r0
|           0x00000e78  ~   0268           ldr r2, [r0]                ; arg1
|           ; UNKNOWN XREF from aav.0x00000189 @ +0x3
|           ;-- aav.0x00000e79:
|           0x00000e79                    unaligned
|           0x00000e7a      0249           ldr r1, [aav.aav.0x00000f3c] ; [0xe84:4]=0xf3c aav.0x00000f3c
|           0x00000e7c      d2f89c22       ldr.w r2, [r2, 0x29c]
|           0x00000e80      7944           add r1, pc                  ; "Hello from C++" section..rodata
\           0x00000e82      1047           bx r2
```

Vediamo i comandi precedenti:

- `e emu.str=true;` abilita l'emulazione tramite radare2.
Grazie a questo comando possiamo vedere la string che stiamo cercando ("Hello from C++")
- `s 0x00000e78` è un seek all'indirizzo `0x00000e78`, in cui si trova la nostra funzione.
Lo eseguiamo in modo che i comandi successivi verranno applicati a questo indirizzo
- `af` sta per analyze function
- `pdf` sta per print disassembly of function

Usando radare2 puoi eseguire velocemente i comandi e uscire usando i flag `-qc '<commands>'`.
Dai passi precedenti sappiamo cosa fare, li mettiamo tutti insieme:

```sh
$ radare2 -qc 'e emu.str=true; s 0x00000e78; af; pdf' HelloWord-JNI/lib/armeabi-v7a/libnative-lib.so
╭ (fcn) sym.Java_sg_vantagepoint_helloworldjni_MainActivity_stringFromJNI 12
│ sym.Java_sg_vantagepoint_helloworldjni_MainActivity_stringFromJNI (int32_t arg1);
│ ; arg int32_t arg1 @ r0
│ 0x00000e78 0268 ldr r2, [r0] ; arg1
│ 0x00000e7a 0249 ldr r1, [0x00000e84] ; [0xe84:4]=0xf3c
│ 0x00000e7c d2f89c22 ldr.w r2, [r2, 0x29c]
│ 0x00000e80 7944 add r1, pc ; "Hello from C++" section..rodata
╰ 0x00000e82 1047 bx r2
```

Nota che in questo caso non stiamo usando il flag `-A`.
Invece, stiamo dicendo a radare2 di analizzare la funzione usando il comando `af`.
Questo è uno dei casi in cui possiamo velocizzare l'analisi perchè ci stiamo focalizzando su una parte specifica dell'app.

#### IDA Pro

Assumiamo che tu abbia aperto `lib/armeabi-v7a/libnative-lib.so` in IDA Pro.
Non appena il file viene caricato, clicca sulla finestra "Functions" sulla sinistra e premi Alt+t per aprire il dialog di ricerca.
Inserisci "java" e premi invio.
Dovrebbe evidenziare la funzione `ava_sg_vantagepoint_helloworld_MainActivity_stringFromJNI`.
Fai doppio click sulla funzione per saltare al suo indirizzo nella finestra del disasembly.
"Ida View-A" dovrebbe mostrare il disasembly della funzione.

```sh
LDR R2, [R0]
LDR R1, =aHelloFromC
LDR.W R2, [R2, #0x29C]
jstring (*NewStringUTF)(JNIEnv*, const char*);
ADD R1, PC
BX R2
```

Non ci sarà molto codice, ma dovresti essere in grado di analizzarlo.
La prima cosa che devi sapere è che il primo argomento passato a ogni funzione JNI è un JNI interface pointer.
Un interface pointer è un puntatore a puntatore.
Questo puntatore punta a una tabella di funzioni: un array di altri puntatori, ognuno dei quali punta a un JNI interface pointer.
La tabella delle funzioni viene inizializzata dalla Java VM e permette alle funzioni native di interagire con l'ambiente Java.

Vediamo ogni linea di codice del disassembly.

`LDR R2, [R0]`

Ricorda: il primo argomento (in R0) è un puntatore al puntatore alla tabella delle funzioni di JNI.
L'istruzione `LDR` carica questa tabella delle funzioni in R2.

`LDR R1, =aHelloFromC`

Questa istruzione carica in R1 l'offset relativo al Program Counter (PC) della string "Hello from C++".
Nota che questa string viene subito dopo la fine del blocco della funzione all'offset 0xe84.
L'indirizzamento relativo al PC permette al codice di essere eseguito indipendentemente dalla sua posizione in memoria.

`LDR.W R2, [R2, #0x29C]`

Questa istruzione carica il puntatore a funzione dall'offset 0x29C nella tabella dei puntatori di funzioni JNI putato da R2.
Corrisponde alla funzione `NewStringUTF`.
Puoi cercare nella lista dei puntatori di funzione in jni.h, che è incluso nell'Android NDK.
Il prototipo di funzione somiglia al seguente:

`jstring (*NewStringUTF)(JNIEnv*, const char*);`

La funzione prende due argomenti:
il puntatore JNIEnv (già in R0) e
un puntatore a String.
Successivamente, il valore corrente di PC viene aggiunto a R1, da cui risulta l'indirizzo assoluto della string statica "Hello from C++" (PC + offset).

`ADD R1, PC`

Infine, il programma esegue una branch instruction per la funzione `NewStringUTF` caricata in R2.

`BX R2`

Quando la funzione ritorna, R0 contiene il puntatore alla string UTF costruita.
Questo è il valore finale restituito, quindi R0 resta invariato e la funzione ritorna.

### Automated Static Analysis

Dovresti usare tool per eseguire un'analisi statica efficiente.
Questi permettono al tester di concentrarsi su business logic più complesse.
É disponibile una pletora di static code analyzer, da scanner open source a scanner enterprise-ready in piena regola.
Il miglior tool per l'incarico dipende dal budget, dai requisiti del cliente, e dalle preferenze del tester.

Alcuni static analyzer si basano sulla disponibilità di codice sorgente;
altri prendono in input l'apk compilata.
Tieni presente che gli static analyzer potrebbero non essere in grado di invididuare tutti i problemi da soli anche se possono aiutarci a concentrarci su potenziali problemi.
Analizza attentamente ciascun problema individuato e prova a capire che cosa sta facendo l'app per aumentare la probabilità di individuare nuove vulnerabilità.

Configura adeguatamente lo static code analyzer per ridurre la probabilità di falsi positivi, e magari scegli solo alcune categorie di vulnerabilità da rilevare durante lo scan.
I risultati degli static analyzer possono essere troppi, e i tuoi sforsi possono essere controproduttivi se devi investigare manualmente in un report esteso.

Ci sono diversi tool open source per analisi di sicurezza automatizzata di un'apk.

- QARK
- Androbugs
- JAADAS
- MobSF

Per i tool enterprise, guarda la sezione "Static Code Analysis" nel capitolo "Testing Tools".

### Dynamic Analysis

L'analisi dinamica testa l'app eseguendo il binario dell'app e analizzandone il flusso al fine di trovare delle vulnerabilità.
Per esempio, le vulnerabilità riguardanti il data storage potrebbero essere difficili da individuare durante l'analisi statica, ma nell'analisi dinamica puoi facilmente individuare quali informazioni sono memorizzate in modo persistente e se queste sono protette adeguatamente.
Oltre a questo, l'analisi dinamica permette al tester di identificare adeguatamente:

- i flussi di business logic
- le vulnerabilità negli ambienti testati
- l'input validation debole e il cattivo input/output encoding, dato che sono eseguiti attraverso uno o più servizi

L'analisi può essere assistita da un tool automatico, come MobSF, durante la valutazione di un'app.
Un'app può essere valutata tramite side-loading, re-packaging o semplicemente attaccando la versione installata.

### Dynamic Analysis on Non-Rooted Devices

I device non-rooted danno al tester due vantaggi:

- replicare un ambiente in cui l'app viene eseguita normalmente
- grazie a tool come objection, puoi fare il patching dell'app per testarla come se fossi su un device rooted (ma sei costretto a restare sempre all'interno della stessa app)

Per analizzare dinamicamente l'app, puoi appoggiarti a objection che sfrutta Frida.
Tuttavia, per poter usare objection su un device non-rooted devi eseguire un passo aggiuntivo: fare il patching dell'apk in modo che includa la libreria Frida gadget.

Per realizzare ciò, puoi lanciare i seguenti comandi:

```sh
# Download the Uncrackable APK
$ wget https://raw.githubusercontent.com/OWASP/owasp-mstg/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk
# Patch the APK with the Frida Gadget
$ objection patchapk --source UnCrackable-Level1.apk
# Install the patched APK on the android phone
$ adb install UnCrackable-Level1.objection.apk
# After running the mobile phone, objection will detect the running frida-server through the APK
$ objection explore
```

### Debugging

267

### Tracing

### Emulation-based Analysis

### Binary Analysis