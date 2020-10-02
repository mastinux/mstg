# Testing User Interaction

## Testing User Education (MSTG-STORAGE-12)

### Informing users on their private information

Quando il programmatore ha bisogno di informazioni personali dell'utente per il business process, 
l'utente deve essere informato su cosa viene fatto ai dati e perchè sono necessari.
Se una terza parte elabora i dati, il programmatore deve informare l'utente.
Infine, ci sono tre processi che deve supportare:

- the right to be forgotten:
un utente deve essere in grado di richiedere la cancellazione dei suoi dati, e avere spiegazione su come farlo
- the right to correct data:
l'utente dovrebbe essere in grado di correggere le sue informazioni personali in qualsiasi momento, e avere spiegazioni su come farlo
- the right to access user data:
l'utente dovrebbe essere in grado di richiedere tutte le informazioni che l'app ha a suo riguardo e all'utente dovrebbe essere spiegato su come richiedere tali informazioni

Quando è necessario elaborare dati aggiuntivi, il programmatore deve chiedere di nuovo il consenso all'utente.

### Informing the user on the best security practices

Ecco una lista di best practice di cui l'utente potrebbe essere informato:

- fingerprint usage:
quando un'app usa le impronte digitali per l'autenticazione e dà accesso a transazioni/operazioni ad alto rischio, 
informare l'utente che ci potrebbero essere dei problemi quando più impronte digitali di diverse persone sono registrate sullo stesso device
- rooting/jailbreaking:
quando l'app rileva un device rooted/jailbroken, 
informa l'utente del fatto che alcune azioni ad alto rischio comporteranno rischi aggiuntivi dovuti allo stato rooted/jailbroken del device
- specific credentials:
quando un utente ottiene un codice di recovery, una password o un pin da un'app, 
avvisa l'utente di non condividerli mai con nessun altro e che solo l'app lo richiederà
- application distribution:
in caso di app ad alto rischio è raccomandato comunicare qual è il modo ufficiale di distribuire l'app.
Altrimenti, gli utenti potrebbero usare altri canali da cui possono scaricare una versione compromessa dell'app
