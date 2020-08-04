# Android Platform APIs

## Testing App Permissions (MSTG-PLATFORM-1)

Android assegna una system identity diversa (user ID e group ID Linux) a ogni app installata.
Poichè ogni app Android opera in una sandbox, le app devono chiedere esplicitamente accesso alle risorse e ai dati che sono al di fuori della propria sandbox.
Richiedono quest'accesso dichiarando i permessi di cui hanno bisogno per usare questi dati e feature di sistema.
In base a quanto i dati o le feature richiesti sono sensibili o critici, il sistema Android darà i permessi in modo automatico o chiederà l'approvazione all'utente.

I permessi Android sono classificati in quattro diverse categorie sulla base del livello di protezione che offrono:

- Normal: 
questa permission dà all'app accesso a feature isolate ad app-level con rischio minimo per le altre app, l'utente e il sistema
- Dangerous: 
questa permission di solito dà all'app il controllo sui dati utente o il controllo sul device per tutto ciò che riguarda l'utente stesso
- Signature: 
la permission viene data solo se l'app richiedente è firmata con lo stesso certificato usato per firmare l'app che ha dichiarato la permission.
Se la firma è verificata, la permission viene data automaticamente
- SystemOrSignature: 
questa permission viene data solo alle app embedded nella system image o firmate con lo stesso certificato usato per firmare l'app che ha dichiarato la permission

#### Activity Permission Enforcement

Le permission sono applicate tramite l'attributo `android:permission` nel tag `<activity>` nel manifest.
Queste permission restringono le applicazioni che possono lanciare l'activity.
Queste permission vengono verificate durante `Context.startActivity` e `Activity.startActivityForResult`.
Se non si posseggono le permission richieste viene lanciata una `SecurityException`.

#### Service Permission Enforcement

Le permission applicate tramite l'attributo `android:permission` nel tag `<service>` nel manifest restringono chi può avviare o agganciarsi al service.
La permission viene verificata durante `Context.startService`, `Context.stopService` e `Context.bindService`.
Se non si posseggono le permission richieste viene lanciata una `SecurityException`.

#### Broadcast Permission Enforcement

Le permission applicate tramite l'attributo `android:permission` nel tag `<receiver>` restringono chi può inviare messaggi broadcast al `BroadcastReceiver`.
Le permission vengono verificate dopo che il metodo `Context.sendBroadcast` è terminato.
Se non si posseggono le permission richieste tuttavia non viene lanciata un'exception, ma semplicemente il messaggio broadcast non viene inviato.

Una permission può essere passata al `Context.registerReceiver` per controllare chi può inviare messaggi broadcast verso un receiver registrato a livello di codice.
Diversamente, una permission può essere fornita alla chiamata di `Context.sendBroadcast` per restringere quali broadcast receiver possono ricevere il messaggio broadcast.

Nota che sia un receiver che un broadcaster possono richiedere una permission.
In questo caso, entrambi i controlli di permission devono essere verificati per l'intent per poter essere associato al target.

#### Content Provider Permission Enforcement

Le permission applicate tramite l'attributo `android:permission` nel tag `<provider>` restringono l'accesso ai dati di un ContentProvider.
I content provider hanno un'importante facility aggiuntiva di sicurezza chiamata URI permission.
Diversamente dagli altri componenti, i ContentProvider hanno due attributi di permission separati che possono essere impostati,
`android:readPermission` restringe chi può leggere dal provider,
e `android:writePermission` restringe chi può scrivere su di esso.
Se un ContentProvider è protetto sia con permessi di lettura che di scrittura, il possesso del solo permesso di scrittura non dà anche i permessi di lettura.

Queste permission sono date quando si recupera un provider (se non si ha la permission, viene lanciata una `SecurityException`), o quando si eseguono operazioni sul provider.
L'uso di `ContentResolver.query` richiede il possesso dei permessi di lettura;
L'uso di `ContentResolver.insert`, `ContentResolver.update` e `ContentResolver.delete` richiede il possesso dei permessi di scrittura.
Viene lanciata una `SecurityException` se non si posseggono le permission adeguate.

#### Content Provider URI Permissions

Il sistema standard di permission non è sufficiente quando viene usato con i content provider.
Per esempio un content provider potrebbe limitare le permission alla sola lettura per proteggersi, usando URI custom per recuperare informazioni.
Un app dovrebbe avere solo le permission per quella specifica URI.

La soluzione sono le permission per-URI.
Quando si avvia o si restiuisce il risutato di un'activity, il metodo può impostare `Intent.FLAG_GRANT_READ_URI_PERMISSION` e/o `Intent.FLAG_GRANT_WRITE_URI_PERMISSION`.
In questo modo si dà la permission all'activity per la specifica URI indipendentemente se ha le permission per accedere ai dati dal content provider.
Si realizza un modello comune secondo capability in cui le interazioni dell'utente portano alla concessione ad-hoc di permission fine-grained.
Ciò può ridurre le permission richieste dalle app a quelle direttamente collegate al loro comportamento.
Senza l'impiego di questo modello, utenti malevoli potrebbero accedere agli allegati di email di altri membri o recuperare una lista di contatti tramite URI non protette.
Nel manifest l'attributo `android:grantUriPermissions` o il node aiutano a restringere le URI.

#### Custom Permissions

Android consente alle app di esporre i propri service/component ad altre app.
Le custom permission sono necessarie per accedere ai componenti esposti dall'app.
Puoi definire custom permission nell'`AndroidManifest.xml` creando un tag permission con due attributi obbligatori: `android:name` e `android:protectionLevel`.

É cruciale creare custom permission che aderiscano al Principle of Least Privilege: la permission andrebbe definita esplicitamente per il suo scopo, con una label e una descrizione significativa e accurata.

### Static Analsysis

214

### Dynamic Analysis
