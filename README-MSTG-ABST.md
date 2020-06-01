# Android Basic Security Testing

### Xposed

Xposed è un framework per moduli che possono modificare il compotamento del sistema e delle app senza cambiare alcuna APK.
Tecnicamente, è una versione estesa di Zygote che esporta API per codice Java in esecuzione quando un nuovo processo viene lanciato.
L'esecuzione di codice Java all'interno del contesto di un'app appena istanziata permette di risolvere, fare l'hook e l'override di metodi Java appartenenti all'app.
Xposed usa la reflection per esaminare e modificare un'app in esecuzione.
Le modifiche vengono applicate in memoria e vengono mantenute solo durante l'esecuzione del processo, dato che il binario dell'app non viene modificato.

Per usare Xposed, è necessario un device rooted.
I moduli possono essere installati attraverso l'installer dell'app Xposed.
Dato che la sola installazione di Xposed è facilmente individuabile da SafetyNet, è consigliabile usare Magisk per installare Xposed.

I setup per Xposed e Frida sono simili.
Entrambi i framework permettono di fare dynamic instrumentation.
Le tipologie di script disponibili sono molto simili.
Xposed include altri script, come Inspeckage che permette di testare più a fondo l'app.

### Adb

`$ adb forward tcp:<host port> tcp:<device port>`

### Angr

Angr è un framework Python per l'analisi di binari.
È utile sia per l'analisi simbolica statica e dinamica.
In altre parole: dato un binario e uno stato richiesto, Angr prova a raggiungere tale stato, usando metodi formali per trovare un path, anche tramite brute forcing.

### Apkx

Apkx è un wrapper Python che agisce da dex converter e Java decompiler.
Automatizza l'estrazione, conversione e decompilazione di APK.

### Dozer

Dozer è un framework di security assessment Android che permette di cercare vulnerabilità di sicurezza in app e device basandosi sul ruolo delle app di terze parti, interagendo con gli endpoint ICP dell'app e il sistema operativo sottostante.
Automatizza alcuni task e può essere esteso con dei moduli.
I moduli sono molto utili e coprono diverse categorie tra cui una categoria scanner che permette di cercare difetti comuni con un semplice comando come il modulo `scanner.provider.injection` che individua SQL injection nei content provider in tutte le app installate sul device.

È necessario installare il dozer agent sul device (`$ adb install dozer.apk`).
Successivamente si avvia una sessione con il device (`$ adb forward tcp:31415 tcp:31415` e `$ dozer console connect`).
A questo punto, è possibile per esempio enumerare la superficie d'attacco di un'app col seguente comando: `$ dx> run app.package.attacksurface <package>`.
Si ottiene una lista di activity, broadcast receiver, content provider e service che sono esposti, cioè sono pubblici e possono essere acceduti da altre app.
Una volta identificata la superficie d'attacco, puoi interagire con gli endpoint IPC tramite dozer senza scrivere un'app standalone separata.
Ad esempio se l'app espone un'activity che espone dati sensibili, puoi invocare il modulo `app.activity.start`: `$ dz> run app.activity.start --component <package> <component-name>`.
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

\# TODO prova dozer

\# TODO continue 114

