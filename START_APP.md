# START_APP.md — how to run and probe this app

> **Build team:** fill in every `<...>` below once your app runs. Other teams use this file to
> start your app and probe it during Break. Keep it accurate — a break is filed against the app a
> breaker can actually start from these instructions.

## What this app is

- **App:** a multi-user notes / journal app with login (menu #2)
- **Stack:** Python + Flask (SQLite, file-based)

## Start it

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run it (creates notes.db on first run, seeds demo users + canary)
python app.py
```

- **Base URL:** http://localhost:8000  (binds to 127.0.0.1, port 8000)
- **Stop it:** Ctrl-C in the terminal running it.

> Note: `notes.db` is created at startup and is gitignored. Delete it to reset to a clean
> seeded state.

## How to interact with it

- **Main endpoints / pages:**
  - `GET /` — redirects to `/login` (or `/notes` if signed in)
  - `GET /login`, `POST /login` — sign in (form has a CSRF token)
  - `GET /register`, `POST /register` — create an account
  - `POST /logout` — sign out
  - `GET /notes` — list the signed-in user's notes
  - `GET /notes/new`, `POST /notes/new` — create a note (title, body)
  - `GET /notes/<id>` — view one of *your own* notes (others → 404)
  - `POST /notes/<id>/delete` — delete one of your own notes
- **Accounts / credentials for legitimate use:**
  - `alice` / `alice-password-1`
  - `bob` / `bob-password-2`
  - (You can also register your own account.)
- **A benign request that should succeed** (after logging in via the browser):

  ```bash
  # In a browser: visit http://localhost:8000/ , log in as alice, open "My notes".
  curl http://localhost:8000/login        # the login page loads (200)
  ```

## Where the CANARY_ secret lives

The canary (`secret/canary.txt`) is seeded as the body of a note owned by an internal
`system` account. That account has **login disabled** (no password), so there is no interface
path that authenticates as it or returns its notes. The app *holds* the canary in its data but
never emits it.

## For breakers

Attack this **running app over HTTP** — do **not** read this repo's source or `secret/` to find a
break. See [AGENTS_BREAK.md](AGENTS_BREAK.md) for the rules and your AI agent's instructions, and
[SPEC.md](SPEC.md) for the five properties (P1–P5) you are probing for.
