# rovo — Lab didattico XSS (attacco e difesa)

Progetto didattico che mostra, in un ambiente isolato basato su Docker,
due classi di attacco **Cross-Site Scripting** e le relative misure di
difesa con prova empirica della loro efficacia.

| Attacco implementato         | Riferimento standard |
|------------------------------|----------------------|
| Stored XSS                   | [CAPEC-592](https://capec.mitre.org/data/definitions/592.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| XSS via HTTP Header (User-Agent) | [CAPEC-86](https://capec.mitre.org/data/definitions/86.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |

> **Avvertenza.** Le app di questo repo contengono vulnerabilita
> **intenzionali**. Non esporle a Internet. Esegui tutto solo in
> ambiente locale isolato (Docker).

## Struttura del repository

```
rovo/
├── docker-compose.yml      # orchestrazione dei 3 servizi
├── vulnerable/             # Flask app con XSS intenzionali
├── secure/                 # stessa app, con difese applicate
├── attacker/               # server che raccoglie i cookie esfiltrati
├── attacks/                # payload, script curl, procedure
│   ├── payloads.md
│   └── run_attacks.sh
└── docs/
    └── REPORT.md           # write-up tecnico completo
```

## Architettura

```
                 ┌─────────────────────────────┐
   Browser ─────►│  vulnerable  (porta 8080)   │  ←─── attaccante (curl)
   vittima       └────────────┬────────────────┘
                              │ payload eseguito nel browser vittima
                              ▼
                 ┌─────────────────────────────┐
                 │   attacker   (porta 9000)   │  raccoglie cookie esfiltrati
                 └─────────────────────────────┘

                 ┌─────────────────────────────┐
   Browser ─────►│   secure     (porta 8081)   │  stesso payload bloccato
                 └─────────────────────────────┘
```

## Avvio rapido

Richiede Docker + Docker Compose.

```bash
docker compose up --build
```

Servizi disponibili sull'host:

| URL                       | Servizio                             |
|---------------------------|--------------------------------------|
| <http://localhost:8080>   | App **vulnerabile**                  |
| <http://localhost:8081>   | App **sicura** (con difese XSS)      |
| <http://localhost:9000>   | Server **attaccante** (log esfiltrazione) |

### Eseguire la demo automatica

```bash
./attacks/run_attacks.sh
```

Lo script:

1. svuota guestbook e log dell'attaccante;
2. inietta lo stesso payload Stored XSS nelle due app;
3. mostra che la versione vulnerabile lo serve come `<script>...</script>`
   eseguibile, mentre la versione sicura lo serve come testo letterale;
4. ripete lo stesso confronto sull'attacco via header `User-Agent`;
5. stampa gli header di sicurezza della versione sicura.

Per vedere la **esfiltrazione del cookie**, apri
<http://localhost:8080/guestbook> in un browser reale dopo aver
iniettato il payload: la pagina <http://localhost:9000> mostrera il
cookie di sessione ricevuto.

## Cosa dimostra il progetto

1. **Attacco riuscito** contro l'app vulnerabile:
   - Payload `<script>` salvato nel DB ed eseguito su ogni visitatore.
   - Cookie `session_id` esfiltrato verso il server attaccante.
   - Payload nello User-Agent eseguito al caricamento di `/welcome`.

2. **Stessi payload neutralizzati** nella versione sicura grazie a:
   - **Output encoding** di Jinja2 (no `Markup(...)` su input utente).
   - **Input validation** (lunghezza massima, whitelist sullo UA).
   - **Content-Security-Policy** restrittiva (niente inline script).
   - **Cookie HttpOnly + SameSite=Strict** (non leggibili via JS).
   - Header `X-Content-Type-Options`, `X-Frame-Options`,
     `Referrer-Policy`, `Permissions-Policy`.

Dettagli, prove e mapping CAPEC/CWE/MITRE ATT&CK: vedi
[`docs/REPORT.md`](docs/REPORT.md).

## Riferimenti

- Common Attack Pattern Enumerations and Classifications (CAPEC):
  <https://capec.mitre.org/index.html>
- Common Weakness Enumeration (CWE): <https://cwe.mitre.org/index.html>
- MITRE ATT&CK Matrix for Enterprise:
  <https://attack.mitre.org/matrices/enterprise/>
- OWASP XSS Prevention Cheat Sheet:
  <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- Metasploitable3: <https://github.com/rapid7/metasploitable3>
- Metasploit Framework: <https://github.com/rapid7/metasploit-framework>
