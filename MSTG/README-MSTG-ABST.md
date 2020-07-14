# Android Basic Security Testing

## Recommended Tools

### Xposed

Xposed è un framework per moduli che possono modificare il compotamento del sistema e delle app senza cambiare l'APK.
Tecnicamente, è una versione estesa di Zygote che esporta API per codice Java in esecuzione quando un nuovo processo viene lanciato.
L'esecuzione di codice Java all'interno del contesto di un'app appena istanziata permette di risolvere, fare l'hook e l'override di metodi Java appartenenti all'app.
Xposed usa la reflection per esaminare e modificare un'app in esecuzione.
Le modifiche vengono applicate in memoria e vengono mantenute solo durante l'esecuzione del processo, dato che il binario dell'app non viene modificato.

Per usare Xposed, è necessario un device rooted.
I moduli possono essere installati attraverso l'installer dell'app Xposed.
Dato che la pura installazione di Xposed è facilmente individuabile da SafetyNet, è consigliabile usare Magisk per installare Xposed.

I setup per Xposed e Frida sono simili.
Entrambi i framework permettono di fare dynamic instrumentation.
Le tipologie di script disponibili sono molto simili.
Xposed include altri script, come Inspeckage che permette di testare più a fondo l'app.

### Adb

Per redirigere il traffico da una porta tcp dell'host a una porta tcp del device:

```sh
$ adb forward tcp:<host port> tcp:<device port>
```
	
Per redirigere il traffico in senso opposto:

```sh
$ adb reverse tcp:<device port> tcp:<host port>
```

### Angr

Angr è un framework Python per l'analisi di binari.
È utile sia per l'analisi simbolica statica e dinamica.
In altre parole: dato un binario e uno stato richiesto, Angr prova a raggiungere tale stato, usando metodi formali per trovare un path, anche tramite brute forcing.

### Apkx

Apkx è un wrapper Python che agisce da dex converter e Java decompiler.
Automatizza l'estrazione, conversione e decompilazione di APK.

### Drozer

Drozer è un framework di security assessment Android che permette di cercare vulnerabilità di sicurezza in app e device basandosi sul ruolo delle app di terze parti, interagendo con gli endpoint ICP dell'app e il sistema operativo sottostante.
Automatizza alcuni task e può essere esteso con dei moduli.
I moduli sono molto utili e coprono diverse categorie tra cui un insieme di scanner che permettono di cercare difetti comuni con un semplice comando, come il modulo `scanner.provider.injection` che individua SQL injection nei content provider in tutte le app installate sul device.

È necessario installare il drozer agent sul device (`$ adb install drozer.apk`).
Successivamente si avvia una sessione con il device emulato (`$ adb forward tcp:31415 tcp:31415` e `$ drozer console connect`).
A questo punto, è possibile per esempio enumerare la superficie d'attacco di un'app col seguente comando: `$ dx> run app.package.attacksurface <package>`.
Si ottiene una lista di activity, broadcast receiver, content provider e service che sono esposti, cioè sono pubblici e possono essere acceduti da altre app.
Una volta identificata la superficie d'attacco, puoi interagire con gli endpoint IPC tramite drozer senza dover scrivere un'app standalone separata.
Ad esempio se l'app espone un'activity che fornisce dati sensibili, puoi invocare il modulo `app.activity.start`: `$ dz> run app.activity.start --component <package> <component-name>`.
Di seguito sono riportati alcuni comandi utili.

	# List all the installed packages
	dz> run app.package.list
	# Find the package name of a specific app
	$ dz> run app.package.list –f (string to be searched)
	# See basic information
	$ dz> run app.package.info –a (package name)
	# Identify the exported application components
	$ dz> run app.package.attacksurface (package name)
	# Identify the list of exported Activities
	$ dz> run app.activity.info -a (package name)
	# Launch the exported Activities
	$ dz> run app.activity.start --component (package name) (component name)
	# Identify the list of exported Broadcast receivers
	$ dz> run app.broadcast.info -a (package name)
	# Send a message to a Broadcast receiver
	$ dz> run app.broadcast.send --action (broadcast receiver name) -- extra (number of arguments)
	# Detect SQL injections in content providers
	$ dz> run scanner.provider.injection -a (package name)

### Frida

- installa Frida (`$ pip install frida-tools`)

- scarica l'ultima versione di `frida-server` da github, in base all'architettura del device

- esegui `frida-server` sul device

```sh
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "su -c /data/local/tmp/frida-server &"
```

- ottieni la lista dei processi in esecuzione

```sh
$ frida-ps -U
```
	
- ottieni la lista di tutte le app installate sul device

```sh
$ frida-ps -Uai
```

- traccia le chiamate a librerie di basso livello (`libc.so`)

```sh
$ frida-trace -U org.lineageos.jelly -i open
```

- interagisci con il processo

```sh
$ frida -U org.lineageos.jelly
```

- carica uno script per il processo

```sh
$ frida -U -l on-resume.js org.lineageos.jelly
```

Il seguente è un esempio di script per fare overwrite della funzione `onResume` della classe Activity:

```javascript
Java.perform(function () {
	var Activity = Java.use("android.app.Activity");
	Activity.onResume.implementation = function () {
		console.log("[*] onResume() got called!");
		this.onResume();
	};
});
```

`Java.perform` assicura che il codice venga eseguito nel contesto della Java VM.
Istanzia un wrapper per la classe `android.app.Activity` tramite `Java.use` e fa l'overwrite della funzione `onResume`.
La nuova implementazione stampa informazioni sulla console e chiama il metodo `onResume` originale invocando `this.onResume`.

Frida permette anche di cercare e manipolare gli oggetti istanziati sull'heap.
Il seguente script cerca istanze di oggetti `android.view.View` e invoca il loro metodo `toString`.

```javascript
setImmediate(function() {
	console.log("[*] Starting script");
	Java.perform(function () {
		Java.choose("android.view.View", {
			"onMatch":function(instance){
				console.log("[*] Instance found: " + instance.toString());
			},
			"onComplete":function() {
				console.log("[*] Finished heap search")
			}
		});
	});
});
```

È possibile sfruttare la reflection di Java.
Per elencare i metodi pubblici della classe `android.view.View`, puoi creare un wrapper per questa classe in Frida e invocare `getMethod` dalla proprietà `class`.

```javascript
Java.perform(function () {
	var view = Java.use("android.view.View");
	var methods = view.class.getMethods();
	for(var i = 0; i < methods.length; i++) {
		console.log(methods[i].toString());
	}
});
```

Frida offre anche delle API usabili in Python, C, NodeJS e Swift.

### Magisk

Magisk è un tool per il rooting dei device Android.
Gli altri tool modificano i dati nella partizione system.
Magisk invece non lo fa, secondo la modalità systemless.
In questo modo le modifiche vengono nascoste alle app sensibili al rooting (es. app bancarie) e permette di usare gli aggiornamenti ufficiali Android senza dover rimuovere l'accesso root.

### MobSF

MoSF è un framework di pentesting di app mobile che supporta i file APK.

### Objection

Objection è un toolkit di esplorazione a runtime, basato su Frida.
Permette di fare security testing su device non rooted.
È richiesto il repackaging dell'app per iniettare il Frida gadget.
In questo modo una volta installata l'APK, è possibile interagire con Frida.
Fornisce anche un REPL per interagire con l'app, dando la possibilità di eseguire qualsiasi operazione eseguibile dall'app.

La possibilità di eseguire analisi dinamiche avanzate su device non rooted rende Objection molto utile.
Un'app potrebbe avere dei controlli RASP che individuano i metodi di rooting e l'injection di un Frida gadget potrebbe essere il metodo più facile per aggirare questi controlli.
Inoltre, gli script Frida inclusi facilitano l'analisi dell'app o l'evasione dei controlli di sicurezza.

Se hai già un device rooted, Objection può connettersi direttamente al Frida server in esecuzione per fornire tutte le sue funzionalità senza dover fare il repackaging dell'app.

- individua il nome dell'app con `frida-ps`

```sh
$ frida-ps -Ua | grep telegram
```

- connettiti all'app

```sh
$ objection --gadget="org.telegram.messenger" explore
```

- tra i vari comandi puoi lanciare

```sh
# Show the different storage locations belonging to the app
$ env
# Disable popular ssl pinning methods
$ android sslpinning disable
# List items in the keystore
$ android keystore list
# Try to circumvent root detection
$ android root disable
```sh

### radare2

radare2 è un framework di reverse engineering per fare disassembling, debugging, patching e analisi di binari.
Offre sia una command line interface che una Web UI (`-H`).

- ricerca stringhe in AndroidManifest.xml

```sh
$ rafind2 -ZS permission AndroidManifest.xml
```

- ottieni informazioni sul file binario

```sh
$ rabin2 -I my-app/classes.dex
```

- caricare binari DEX (da qui puoi lanciare una serie di comandi per interagire dinamicamente)

```sh
$ r2 classes.dex
```

### r2frida

r2frida sfrutta sia radare2 che Frida, unendo effettivamente le capacità di reverse engineering di radare2 con il toolkit di dynamic instrumentation di Frida.

## Obtaining and Extracting Apps

Uno dei metodi più semplici per ottenere un APK è scaricarla dai siti che fanno da mirror.
Tali siti non sono ufficiali e non c'è garanzia che l'app non sia stata reimpacchettata o contenga malware.
Potresti usare APKMirror o APKPure, ma usali solo se sono l'ultima opzione.

Invece il metodo raccomandato è l'estrazione dell'APK direttamente dal dispositivo.
Puoi lanciare il comando `$ adb shell pm path <package name>` per creare l'APK sul device oppure usare APKExtractor.

## Information Gathering

Puoi ottenere la lista delle app installate lanciando il seguente comando:

```sh
$ adb shell pm list packages
```
	
Puoi ottenere solo le app di terze parti e il path della loro APK lanciando il seguente comando:

```sh
$ adb shell pm list packages -3 -f
```
	
Per otterenere lo stesso risultato per una specifica app:

```sh
$ adb shell pm path org.lineageos.jelly
```
	
Ottieni lo stesso risultato usando Frida:

```sh
$ frida-ps -Uai
```
	
Una volta ottenuta l'APK, puoi estrarne il contenuto usando `$ unzip my.apk`.
Troverai:

- AndroidManifest.xml
- META-INF: contenente i metadati dell'app
- assets
- classes.dex: classi compilate nel formato DEX
- lib
- res: risorse non compilate già presenti in resources.arsc
- resources.arsc: risorse precompilate

Usando `unzip` alcuni file, come AndroidManifest.xml, non sono leggibili.
Allora usa `apktool d`.

Puoi ispezionare la directory `lib` contenuta nei file estratti dall'APK, per avere un'idea delle librerie native utilizzate.

Con objection posso ottenere la lista delle directory usate dall'app una volta che è installata:

```sh
$ objection -g org.lineageos.jelly explore
```
	
Tra queste trovo:

- `/data/data/[package-name]` o `/data/user/0/[package-name]`: directory dati interna
- `/storage/emulated/0/Android/data/[package-name]` o `/sdcard/Android/data/[package-storage]`: directory dati esterna
- `/data/app/`: path del package dell'app

La directory dati interna contiene le seguenti directory:

- cache: caching di dati
- code_cache: caching del codice
- lib: librerie native scritte in C/C++
- shared_prefs: file XML contenente le SharedPreferences
- files: file creati dall'app
- databases: SQLite database generati dall'app

L'app potrebbe salvare dati in `/data/data/[package-name]`.

Per ottenere il log di una specifica app puoi usare il seguente comando:

```sh
$ adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

## Setting up a Network Testing Environment

\# FIXME wireshark non riceve traffico

Per fare lo sniffing remoto del traffico da un device emulato, fai il pipe di `tcpdump` su `nc`:

```sh
$ adb shell tcpdump -i wlan0 -s0 -w - | nc -l -p 11111
```

Per accedere alla porta 11111, devi fare il forwarding verso il tuo host:

```sh
$ adb forward tcp:11111 tcp:11111
```
	
Puoi poi connetterti alla porta in forward e usare Wireshark:

```sh
$ nc localhost 11111 | wireshark -k -S -i -
```

Firebase Cloud Messaging (FCM), successore di Google Cloud Messaging (GCM), permette di scambiare messaggi tra un application server e le client app.
Queste entità comunicano tramite il connection server.
I downstream message (push notification) sono inviati dall'application server alle client app.
Gli upstream message sono inviati dalle client app all'application server.
FCM supporta HTTP (porte 8228, 5229, 5230) e XMPP (porte 5235, 5236).
Per esempio su Mac OS X, poi configurare il port forwarding locale lanciando:

```sh
$ echo "
rdr pass inet proto tcp from any to any port 5228-> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5229 -> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5230 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

```sh
$ echo "
rdr pass inet proto tcp from any to any port 5235-> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5236 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

L'intercepting proxy dovrà mettersi in ascolto sulla porta specificata (8080).
Le push notification potrebbero essere cifrate tramite Capillary.

### Bypass the Network Security Configuration

Da Android 7.0 in avanti, la network security configuration (`network_security_config.xml`) permette alle app di personalizzare le proprie impostazioni di sicurezza della rete, indicando quali certificati di CA sono fidati dall'app.

La network security configuration viene impostata in base all'attributo src: `<certificates src=["system" | "user" | "raw resource"] overridePins=["true" | "false"] />`.
I certificati delle CA fidati dall'app possono essere di sistema o definiti dall'utente.
Il caso "user" permette di forzare l'app a fidarsi del certificato caricato dall'utente, secondo la seguente configurazione:

```xml
<network-security-config>
	<base-config>
		<trust-anchors>
			<certificates src="system" />
			<certificates src="user" />
		</trust-anchors>
	</base-config>
</network-security-config>
```

Per poter sfruttare la modifica:

- decompila l'APK:

```sh
$ apktool d my.apk
```
	
- modifica il file `network_security_config.xml` aggiungendo `<certificates src="user" />`

- ricrea l'APK

```sh
$ cd my
$ apktool b
```

Se l'app adotta protezioni addizionali, come la verifica della firma, l'app potrebbe non essere più lanciabile.
Potresti disabilitare tali controlli modificandoli o facendo l'instrumentation dinamica tramite Frida.
Questo processo è automatizzato da [Android-CertKiller](https://github.com/51j0/Android-CertKiller).

Non volendo modificare tutte le APK delle app installate sul device, è possibile forzare il device a fidarsi del certificato del proxy usando [MagiskTrustUserCerts](https://github.com/NVISO-BE/MagiskTrustUserCerts), che inserisce i certificati caricati dall'utente in quelli di sistema.

Per aggiungere il certificato del proxy in quelli fidati a livello di sistema

```sh
$ adb remount

$ openssl x509 -inform der -in cacert.der -outform pem -out cacert.pem
$ openssl x509 -inform pem -subject_hash_old -in cacert.pem
$ cp cacert.pem <hash>.0

$ adb push <hash>.0 /system/etc/security/cacerts
$ adb shell chmod 644 /system/etc/security/cacerts/<hash>.0

$ adb shell reboot
```

Una volta impostato un intercepting proxy e aver assunto una posizione di MITM potresti non vedere ancora traffico.
Questo potrebbe essere dovuto a due ragioni:
l'app usa un framework come Xamarin che non usa le impostazioni proxy di Android oppure
l'app verifica se è in uso un proxy e blocca qualsiasi comunicazione.
Le soluzioni possibili prevedono l'uso di bettercap o iptables.
Potresti usare un access point sotto il tuo controllo per redirigere il traffico, ma questa soluzione richiederebbe hardware aggiuntivo.
In entrambi i casi in Burp è necessario abilitare `Support invisible proxing` in `Proxy` > `Options` > `Edit Interface`.

Sul device puoi usare iptables per redirigere tutto il traffico verso l'intercepting proxy in ascolto sulla porta 8080:

```sh
 $ iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <your-ip-addr>:8080
```

Verifica poi lo stato di iptables:

```sh
$ iptables -t nat -L
```

Per pulire la configurazione di iptables:

```sh
$ iptables -t nat -F
```

In alternativa a iptables, puoi usare bettercap.
Il tuo host deve essere connesso alla stessa rete wireless del device.

```sh
# bettercap -eval "set arp.spoof.targets <device-ip>; arp.spoof on; set arp.spoof.internal true; set arp.spoof.fullduplex true;"
```

Oltre all'uso di iptables e bettercap è possibile usare Frida.
Interrogando la classe `ProxyInfo` è possibile determinare se un proxy è in uso, controllando i metodi `getHost()` e `getPort()`.
Se l'app non usa questa classe, sarà necessario decompilare l'APK e individuare la classe e i relativi metodi usati per il controllo.
Se l'app usa semplicemente il metodo `Proxy.isProxySet()` puoi usare il seguente codice:

```javascript
setTimeout(function(){
	Java.perform(function (){
		console.log("[*] Script loaded")
		var Proxy = Java.use("<package-name>.<class-name>")
		Proxy.isProxySet.overload().implementation = function() {
			console.log("[*] isProxySet function invoked")
			return false
		}
	});
});
```

