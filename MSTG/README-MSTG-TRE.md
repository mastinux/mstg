# Tampering and Reverse Engineering

## Binary Patching

Il Patching consiste nel cambiare l'app compilata:
cambiare il codice negli eseguibili binari,
modificare il bytecode Java
o modificare le risorse.
Si fa riferimento a tale processo col termine modding.
Le patch possono essere applicate in diversi modi, tra cui
modificando i file binari in un editor esadecimale e 
decompilando, modificando e riassemblando un'app.

Attualmente i sistemi operativi mobile impongono la firma del codice, quindi l'esecuzione di app modificate non è così semplice come nell'ambito desktop.
Tuttavia, non è particolarmente difficile fare patching su app eseguite sul tuo device; infatti devi rifirmare l'app o disabilitare la verifica della firma sul codice.

## Code Injection

La code injection permette di esplorare e modificare un processo a run time.
La modifica dei processi in memoria è molto più difficile da individuare rispetto al patching, risulta quindi il metodo preferito.

### Frida

Frida inietta un JavaScript engine nell'instrumented process, scrivendo il codice direttamente nella memoria del processo.
Quando viene agganciata a un'app in esecuzione:

- Frida usa ptrace per dirottare un thread di un processo in esecuzione.
Al processo viene assegnata una porzione di memoria che viene popolata con un mini-bootstrapper
- il bootstrapper avvia un nuovo thread, si connette al Frida debugging server che è in esecuzione sul device e carica le librerie condivise (`frida-agent.so`)
- l'agent instaura un canale di comunicazione bidirezionale verso il tool
- il thread dirottato viene riportato al suo stato originale e l'esecuzione del processo continua normalmente

Frida offre tre modi di operare:

- injected:
è lo scenario più comune in cui il frida-server è in esecuzione sul device.
frida-core è esposto su TCP, in ascolto di default su localhost:27042.
È utilizzabile solo su device rooted/jailbroken
- embedded:
utilizzabile su device rooted/jailbroken e puoi fare l'embedding della libreria fridga-gadget nell'app
- preloaded:
simile a `LD_PRELOAD` o `DYLD_INSERT_LIBRARIES`.
Puoi configurare in modo che il frida-gadget venga eseguito autonomamente e carichi uno script dal filesystem

Frida offre anche i seguenti tool:

- `frida` per script prototyping veloce e scenari try/error
- `frida-ps` per la lista di tutte le app e i processi in esecuzione sul device
- `frida-ls-devices` per la lista dei device connessi
- `frida-trace` per tracciare velocemente i metodi che fanno parte di un'app iOS o che sono implementati in una libreria nativa Android

