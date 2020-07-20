## OMTG-DATAST-004-3RD-PARTY

Exploit:

- intercetta le richieste tramite un proxy

-  la richiesta intercettata è simile alla seguente:

```
POST /acra/_design/acra-storage/_update/report HTTP/1.1
Authorization: Basic TW1IWk9xeEFkVDBtV1NtWGRkWUJkTFBEbzpNbUhaT3F4QWRUMG1XU21YZGRZQmRMUERv
User-Agent: Android ACRA 4.9.0
Accept: text/html,application/xml,application/json,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Content-Type: application/json
Content-Length: 3044
Host: sushi2k.cloudant.com
Connection: close
Accept-Encoding: gzip, deflate

{
    [sensitive data omitted]
}

```

- l'app invia dati sensibili a terze parti
