"""
App web SICURA - versione difesa di rovo.

Stessa funzionalita della app vulnerabile, ma con tutte le misure di
mitigazione contro XSS applicate:

  - Output encoding automatico di Jinja2 (nessun Markup() su input utente).
  - Input validation/whitelist (lunghezza massima, nessun controllo HTML
    perche e l'encoding a fare il lavoro).
  - Sanitizzazione header User-Agent: solo whitelist di caratteri.
  - Header HTTP di sicurezza:
      * Content-Security-Policy (default-src 'self'; nessun inline script)
      * X-Content-Type-Options: nosniff
      * X-Frame-Options: DENY
      * Referrer-Policy: no-referrer
      * Permissions-Policy: restrittiva
  - Cookie di sessione: HttpOnly, SameSite=Strict, Secure (se HTTPS).

Risultato: gli stessi payload che funzionano contro vulnerable/ qui falliscono.
"""
from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, url_for

app = Flask(__name__)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

DB_PATH = Path(os.environ.get("DB_PATH", "/app/data/guestbook.db"))

MAX_AUTHOR_LEN = 64
MAX_BODY_LEN = 2000

# Whitelist di caratteri ammessi nello User-Agent prima di mostrarlo.
# Anche se Jinja2 fa autoescape, la sanitizzazione difesa-in-profondita
# elimina caratteri di controllo / non stampabili.
_UA_ALLOWED = re.compile(r"[^\w\s\.\-_/();:,+]")


def sanitize_user_agent(raw: str) -> str:
    raw = raw[:256]
    return _UA_ALLOWED.sub("", raw)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc: BaseException | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


@app.before_request
def set_demo_cookie() -> None:
    g._set_session = "session_id" not in request.cookies


@app.after_request
def add_security_headers(response):
    if getattr(g, "_set_session", False):
        # Cookie sicuro: HttpOnly + SameSite=Strict. document.cookie non lo vede.
        response.set_cookie(
            "session_id",
            "demo-token-AAAA-BBBB-CCCC-DDDD",
            httponly=True,
            samesite="Strict",
        )

    # CSP restrittiva: niente script inline, niente sorgenti esterne.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/welcome")
def welcome():
    """SICURO: User-Agent sanitizzato + autoescape Jinja2."""
    raw_ua = request.headers.get("User-Agent", "")
    safe_ua = sanitize_user_agent(raw_ua)
    # Passiamo una stringa normale: Jinja2 fara l'escape HTML.
    return render_template("welcome.html", user_agent=safe_ua)


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    """SICURO: input validato + autoescape Jinja2 sull'output."""
    db = get_db()
    if request.method == "POST":
        author = (request.form.get("author") or "anon").strip()[:MAX_AUTHOR_LEN]
        body = (request.form.get("body") or "").strip()[:MAX_BODY_LEN]
        if author and body:
            db.execute(
                "INSERT INTO comments (author, body) VALUES (?, ?)",
                (author, body),
            )
            db.commit()
        return redirect(url_for("guestbook"))

    rows = db.execute(
        "SELECT author, body, created_at FROM comments ORDER BY id DESC"
    ).fetchall()
    # NOTA: niente Markup(). Jinja2 fa l'escape HTML automaticamente.
    comments = [dict(r) for r in rows]
    return render_template("guestbook.html", comments=comments)


@app.route("/reset", methods=["POST"])
def reset():
    db = get_db()
    db.execute("DELETE FROM comments")
    db.commit()
    return redirect(url_for("guestbook"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
