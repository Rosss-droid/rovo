"""
App web VULNERABILE - per scopi didattici.

Contiene due vulnerabilita XSS intenzionali:

1. Stored XSS (CAPEC-592, CWE-79):
   - L'endpoint /guestbook salva commenti in SQLite e li rende
     nel template marcandoli come "safe" -> nessun escape HTML.
2. HTTP Header XSS (CAPEC-86, CWE-79):
   - L'endpoint /welcome riflette l'header User-Agent direttamente
     nel template senza sanitizzazione.

NON ESEGUIRE QUESTO SERVIZIO ESPOSTO SU INTERNET.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, url_for
from markupsafe import Markup

app = Flask(__name__)

# Cookie volutamente NON HttpOnly: cosi un payload JS puo leggerlo via
# document.cookie ed esfiltrarlo. Mostra l'impatto reale di un XSS.
app.config["SESSION_COOKIE_HTTPONLY"] = False

DB_PATH = Path(os.environ.get("DB_PATH", "/app/data/guestbook.db"))


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
    # Cookie "di sessione" finto, usato per dimostrare il furto via XSS.
    if "session_id" not in request.cookies:
        # Nota: lo settiamo nella response in after_request.
        g._set_session = True
    else:
        g._set_session = False


@app.after_request
def write_demo_cookie(response):
    if getattr(g, "_set_session", False):
        # Cookie NON HttpOnly per la dimostrazione didattica.
        response.set_cookie(
            "session_id",
            "demo-token-AAAA-BBBB-CCCC-DDDD",
            httponly=False,
            samesite=None,
        )
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/welcome")
def welcome():
    """VULNERABILE: HTTP Header XSS (CAPEC-86).

    Riflette User-Agent senza escape, marcandolo come Markup safe.
    """
    raw_ua = request.headers.get("User-Agent", "")
    # *** Vulnerabilita: Markup() dice a Jinja "fidati, non scappare" ***
    unsafe_ua = Markup(raw_ua)
    return render_template("welcome.html", user_agent=unsafe_ua)


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    """VULNERABILE: Stored XSS (CAPEC-592).

    Salva il body cosi com'e e lo rende come Markup safe.
    """
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anon")
        body = request.form.get("body", "")
        db.execute(
            "INSERT INTO comments (author, body) VALUES (?, ?)",
            (author, body),
        )
        db.commit()
        return redirect(url_for("guestbook"))

    rows = db.execute(
        "SELECT author, body, created_at FROM comments ORDER BY id DESC"
    ).fetchall()
    comments = [
        {
            "author": Markup(r["author"]),  # *** vulnerabile ***
            "body": Markup(r["body"]),      # *** vulnerabile ***
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    return render_template("guestbook.html", comments=comments)


@app.route("/reset", methods=["POST"])
def reset():
    """Utility didattica: svuota il guestbook."""
    db = get_db()
    db.execute("DELETE FROM comments")
    db.commit()
    return redirect(url_for("guestbook"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
