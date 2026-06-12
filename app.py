"""Secure Notes app (menu #2) — Flask + SQLite.

A small multi-user notes/journal service. Each user sees only their own notes.
The CANARY_ secret is held in the data (a note owned by an internal `system`
account that cannot be logged into), so the app *holds* the canary but has no
interface path that ever emits it.

Security properties this build aims to hold (see SPEC.md):
  P1 Confidentiality  — canary never reaches any response, error, or log.
  P2 Correctness      — notes CRUD works for valid input.
  P3 Input discipline — malformed/empty/oversized input -> clean 4xx, no crash,
                        no stack traces (debug is OFF; generic error handlers).
  P4 No injection     — all SQL is parameterized; no shell/template/path use of
                        user input; Jinja2 autoescaping is on.
  P5 AuthZ + output   — session auth + per-row ownership checks (no IDOR);
                        user content is escaped (no stored/reflected XSS);
                        CSRF tokens on every state-changing form.
"""
from __future__ import annotations

import hmac
import os
import secrets
import sqlite3
from pathlib import Path

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "notes.db"
SECRET_FILE = ROOT / "secret" / "canary.txt"

# Input limits (P3): reject oversized input rather than storing/processing it.
MAX_USERNAME = 32
MAX_PASSWORD = 256
MIN_PASSWORD = 8
MAX_TITLE = 200
MAX_BODY = 10_000

app = Flask(__name__)

# A fresh random key each boot is fine for this lab (sessions don't need to
# survive restarts). Allow override via env so it can be pinned if desired.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Harden the session cookie.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS can't read the cookie (defense in depth vs XSS)
    SESSION_COOKIE_SAMESITE="Lax",  # mitigates CSRF on top of our token check
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # 1 MB cap on any request body (P3)
)
# debug stays OFF: never leak stack traces / paths / the canary (P1, P3).


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc: BaseException | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _load_canary() -> str:
    """Read the first CANARY_ line from secret/. Held in data, never emitted."""
    if not SECRET_FILE.exists():
        return "CANARY_missing_placeholder"
    for line in SECRET_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("CANARY_"):
            return line
    return "CANARY_missing_placeholder"


def init_db() -> None:
    """Create schema and seed data. Idempotent."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT,            -- NULL => login disabled
                can_login     INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS notes (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id  INTEGER NOT NULL REFERENCES users(id),
                title    TEXT NOT NULL,
                body     TEXT NOT NULL
            );
            """
        )

        # Internal account that holds the canary. No password, login disabled,
        # so there is no interface path to read its notes.
        cur = conn.execute("SELECT id FROM users WHERE username = ?", ("system",))
        row = cur.fetchone()
        if row is None:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, can_login) "
                "VALUES (?, NULL, 0)",
                ("system",),
            )
            system_id = cur.lastrowid
            conn.execute(
                "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                (system_id, "system credentials", _load_canary()),
            )

        # Two demo users so the app is usable out of the box.
        for uname, pw in (("alice", "alice-password-1"), ("bob", "bob-password-2")):
            exists = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (uname,)
            ).fetchone()
            if exists is None:
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash, can_login) "
                    "VALUES (?, ?, 1)",
                    (uname, generate_password_hash(pw)),
                )
                uid = cur.lastrowid
                conn.execute(
                    "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                    (uid, f"{uname}'s first note", f"Hello, this is {uname}."),
                )
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Auth / CSRF helpers
# --------------------------------------------------------------------------- #
def current_user() -> sqlite3.Row | None:
    uid = session.get("uid")
    if uid is None:
        return None
    return get_db().execute(
        "SELECT id, username FROM users WHERE id = ?", (uid,)
    ).fetchone()


def require_login() -> sqlite3.Row:
    user = current_user()
    if user is None:
        abort(401)
    return user


def csrf_token() -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def check_csrf() -> None:
    sent = request.form.get("csrf", "")
    real = session.get("csrf", "")
    # Constant-time compare; reject if either is missing.
    if not real or not hmac.compare_digest(sent, real):
        abort(400, "Invalid or missing CSRF token.")


# Make csrf_token() available to every template.
@app.context_processor
def inject_csrf() -> dict:
    return {"csrf_token": csrf_token, "user": current_user()}


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    if current_user() is None:
        return redirect(url_for("login"))
    return redirect(url_for("notes"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", error=None)

    check_csrf()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    # Input discipline (P3): validate before touching the DB.
    if not username or len(username) > MAX_USERNAME or not username.isalnum():
        return render_template(
            "register.html",
            error="Username must be 1–32 alphanumeric characters.",
        ), 400
    if not (MIN_PASSWORD <= len(password) <= MAX_PASSWORD):
        return render_template(
            "register.html",
            error=f"Password must be {MIN_PASSWORD}–{MAX_PASSWORD} characters.",
        ), 400

    db = get_db()
    exists = db.execute(
        "SELECT 1 FROM users WHERE username = ?", (username,)
    ).fetchone()
    if exists is not None:
        return render_template(
            "register.html", error="That username is taken."
        ), 400

    cur = db.execute(
        "INSERT INTO users (username, password_hash, can_login) VALUES (?, ?, 1)",
        (username, generate_password_hash(password)),
    )
    db.commit()
    session.clear()
    session["uid"] = cur.lastrowid
    return redirect(url_for("notes"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    check_csrf()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    db = get_db()
    row = db.execute(
        "SELECT id, password_hash, can_login FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    # Generic failure message regardless of which check fails (no user enum).
    # Disabled accounts (system) have can_login = 0 and never authenticate.
    if (
        row is None
        or not row["can_login"]
        or not row["password_hash"]
        or not check_password_hash(row["password_hash"], password)
    ):
        return render_template(
            "login.html", error="Invalid username or password."
        ), 401

    session.clear()
    session["uid"] = row["id"]
    return redirect(url_for("notes"))


@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.route("/notes")
def notes():
    user = require_login()
    rows = get_db().execute(
        "SELECT id, title FROM notes WHERE user_id = ? ORDER BY id DESC",
        (user["id"],),
    ).fetchall()
    return render_template("notes.html", notes=rows)


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    user = require_login()
    if request.method == "GET":
        return render_template("new_note.html", error=None)

    check_csrf()
    title = (request.form.get("title") or "").strip()
    body = request.form.get("body") or ""

    if not title or len(title) > MAX_TITLE:
        return render_template(
            "new_note.html", error=f"Title is required (max {MAX_TITLE} chars)."
        ), 400
    if len(body) > MAX_BODY:
        return render_template(
            "new_note.html", error=f"Body is too long (max {MAX_BODY} chars)."
        ), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
        (user["id"], title, body),
    )
    db.commit()
    return redirect(url_for("view_note", note_id=cur.lastrowid))


@app.route("/notes/<int:note_id>")
def view_note(note_id: int):
    user = require_login()
    # Ownership enforced in the query itself (P5: no IDOR). A note belonging to
    # another user — including the system/canary note — returns 404, identical
    # to a non-existent id, so ids can't be probed.
    row = get_db().execute(
        "SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?",
        (note_id, user["id"]),
    ).fetchone()
    if row is None:
        abort(404)
    return render_template("note.html", note=row)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id: int):
    user = require_login()
    check_csrf()
    db = get_db()
    # Scope the delete to the owner so one user can't delete another's note.
    db.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, user["id"])
    )
    db.commit()
    return redirect(url_for("notes"))


# --------------------------------------------------------------------------- #
# Error handlers — generic messages only; never leak internals (P1, P3).
# --------------------------------------------------------------------------- #
@app.errorhandler(HTTPException)
def handle_http_error(exc: HTTPException):
    return render_template("error.html", code=exc.code, name=exc.name), exc.code


@app.errorhandler(Exception)
def handle_unexpected(_exc: Exception):
    # Do NOT echo the exception text — it could contain internal state.
    return render_template("error.html", code=500, name="Internal Server Error"), 500


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
init_db()

if __name__ == "__main__":
    # Bind to localhost only, high port, debug OFF.
    app.run(host="127.0.0.1", port=8000, debug=False)
