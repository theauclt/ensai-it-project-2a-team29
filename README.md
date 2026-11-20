# Anonymia

Anonymia receives a text, detects the personal data in it (e-mail, phone number, NIR, IBAN,
license plates, names, places, dates of birth...) using regular expressions, an optional spaCy NER
model and an LLM, then returns the redacted text (masking or pseudonymisation). Every processing is
archived (document hash, strategy, number and types of PII, anti-injection verdicts), never the
content itself. Supervisors and administrators can read the history.

ENSAI 2A project, team 29. This file is enough to install, run and test the application.
Anonymia is a redaction aid, not a guarantee: a human review is still necessary.

## 1. Requirements

- Python 3.12 or later, Git
- A PostgreSQL database (the Datalab one)
- Optional: a key for the Datalab LLM. Without it, the API works with regular expressions only
  (`LLM_ENABLED=false`).

## 2. Installation

From the root of the repository (the folder that contains `pyproject.toml`):

    python -m venv .venv
    source .venv/bin/activate          # Windows: .venv\Scripts\activate
    pip install -e ".[dev]"

Only redo this if `pyproject.toml` changes. Reactivate the environment in every new terminal.
NER detector (optional): `pip install -e ".[ner]"` then `python -m spacy download fr_core_news_lg`.

## 3. Configuration

    cp .env.exemple .env

The `.env` file is ignored by Git: never share it and never commit it.

| Variable | Purpose |
|---|---|
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DATABASE`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_SCHEMA` | Database |
| `JWT_SECRET` | Token signing secret, **at least 32 characters** (without it, the API refuses to start) |
| `ADMIN_LOGIN`, `ADMIN_PASSWORD` | Initial administrator account, created at startup if it does not exist (8 characters minimum, 72 bytes maximum) |
| `LOGIN_MAX_ECHECS`, `LOGIN_FENETRE_SECONDES`, `LOGIN_VERROUILLAGE_SECONDES` | Brute-force protection: by default, 5 failures within 15 min block the login for 15 min (error 429). `LOGIN_MAX_ECHECS=0` disables the limit |
| `INJECTION_SEUIL_ALERTE`, `INJECTION_SEUIL_DESACTIVATION` | Prompt-injection attempts per account: flagged at 3, automatically disabled at 10 (defaults) |
| `LLM_ENABLED` | `false`: regular expressions only |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `LLM_TIMEOUT` | LLM (Datalab: `https://llm.lab.sspcloud.fr/api`, model `qwen3-8-27b`) |
| `LLM_JUDGE_ENABLED`, `LLM_JUDGE_MODEL` | LLM injection judge (active with the LLM, it doubles the LLM calls) |
| `NER_ENABLED`, `SPACY_MODEL` | spaCy NER detector (disabled by default) |

Generate a JWT secret:

    python -c "import secrets; print(secrets.token_urlsafe(48))"

Datalab LLM key: log in at https://llm.lab.sspcloud.fr/, copy the access key from your profile
into `LLM_API_KEY`. Project rule: never use a commercial LLM API on real content.

## 4. Prepare the database

    python -m anonymia.data.init_db

Run it again after every `git pull`: the command adds new columns without deleting anything.
Without it, the API answers 500 (`UndefinedColumn`).

Accounts: the administrator is created when the API starts if `ADMIN_LOGIN` and `ADMIN_PASSWORD`
are in `.env`. Otherwise, or for the other accounts (the password is asked on the keyboard):

    python -m scripts.create_user admin ADMIN
    python -m scripts.create_user sup SUPERVISOR
    python -m scripts.create_user alice USER
    python -m scripts.check_db admin <password>     # checks the database and the authentication

## 5. Run the API

    uvicorn anonymia.main:app --reload

Interactive documentation: http://localhost:8000/docs. On the Datalab (VSCode), the API goes
through a proxy: add `--root-path /proxy/8000`, then open `.../proxy/8000/docs`.

## 6. Streamlit interface

In a second terminal, **after** the API:

    source .venv/bin/activate
    python -m streamlit run interface/app.py

Pages depend on the role: Caviardage (redaction, everyone), Tableau de bord (dashboard), Historique
(history, SUPERVISOR and ADMIN), Administration (ADMIN). The interface contains no logic: everything
goes through the API.

## 7. Use the API from `/docs`

1. `POST /auth/connexion` with `{"login": "...", "mot_de_passe": "..."}`: copy `access_token`.
2. Click "Authorize" and paste the token **without** "Bearer". It expires after 30 minutes.
3. Call the routes:

| Route | Role | Body |
|---|---|---|
| `POST /documents/caviarder` | everyone | `{"contenu": "...", "strategie": "masking"}` (or `pseudonymization`); `"confirmer": true` if an injection is suspected |
| `POST /documents/analyser` | everyone | `{"contenu": "..."}`: PII with position and confidence, no redaction; archived like a redaction (strategy `analyse`); `"confirmer": true` if an injection is suspected |
| `GET /documents/strategies` | everyone | |
| `GET /journaux` | SUPERVISOR, ADMIN | filters: `utilisateur`, `date_debut`, `date_fin` |
| `/admin/utilisateurs...` | ADMIN | list (with `tentatives_injection` and `comportement_dangereux`), creation, role, activation, deletion |

There is no free registration: the administrator creates the accounts. The role is read from the
token: 403 for a route forbidden to the role.

Examples: `{"contenu": "Écrire à jean@mail.fr ou au 06 12 34 56 78.", "strategie": "masking"}`
returns `Écrire à [EMAIL_1] ou au [TEL_1].`; with pseudonymisation, `utilisateur1@example.com`
and `06 00 00 00 01`. The same value always gets the same marker. A pseudonym never reuses a real
value of the document.

Expected errors: 401 without a token or with a wrong password, 403 wrong role, 400 unknown
strategy, 422 empty content or password longer than 72 bytes.

## 8. Tests and quality

    ruff check .
    pytest --cov=anonymia --cov-branch --cov-report=term-missing

No real database or LLM needed. Before every commit, both commands must pass.

## 9. Evaluation on the test corpus

    python -m scripts.evaluer_corpus corpus-test            # regular expressions and injection filter
    python -m scripts.evaluer_corpus corpus-test --llm      # with the LLM
    python -m scripts.evaluer_juge corpus-test              # LLM injection judge (68 LLM calls)

The tables (`metriques.md`, `metriques_juge.md`) are written in the `--sortie` folder.

## 10. Security: what you need to know

- Prompt-injection filter (pattern list): blocks the document until it is confirmed
  (`confirmer: true`). It is a signal, not a barrier: it only covers known wordings.
- LLM injection judge: informs, never blocks, and can be fooled by the document it reads.
  "Nothing found" does not prove that a document is safe.
- PII confidence: the LLM one is a self-assessment. It informs, it never decides what is
  redacted: every detected PII is redacted.
- Degraded mode: if the LLM is unavailable, the API goes on with regular expressions only
  (the `mode_degrade` field says so); names, places and dates of birth may then not be redacted.
- History: if archiving fails, the request fails (no processing without a trace).
  Deleting an account keeps its processings (`user_id` becomes empty).
- Injection attempts: every submission of a document that the filter finds suspicious (on
  `/caviarder` as well as on `/analyser`) counts as an attempt for the account that sends it, even if
  it is the same document. A document that is blocked and then sent again with `"confirmer": true`
  counts only once. At 3 attempts, the account is flagged "dangerous behaviour" in the
  administrator's list of accounts. At 10, it is automatically disabled (403 on the current
  request) until an administrator re-enables it; the counter is not reset, so the next attempt
  disables it again. ADMIN accounts are flagged but never automatically disabled. Only the
  document hash is kept.
- Token: 30 minutes, not revocable, but the account is read from the database on every request:
  a deactivation or a role change applies immediately.
- Maximum document size: 100,000 characters.

## 11. Common problems

| Symptom | Cause and remedy |
|---|---|
| "Failed to load API definition" | Start uvicorn with `--root-path /proxy/8000` |
| "JWT_SECRET manquante" or "trop court" (missing or too short) | Set a secret of at least 32 characters in `.env` |
| "ADMIN_PASSWORD trop court" or "trop long" (too short or too long) | 8 characters minimum, 72 bytes maximum |
| Error on the `users` table at the first start | Run `python -m anonymia.data.init_db` |
| 500 with `UndefinedColumn` | Run `python -m anonymia.data.init_db` again, then the API |
| `KeyError: 'POSTGRES_HOST'` | `.env` missing or incomplete, or command run outside the root folder |
| 401 although the password is right | The account does not exist in this database, or it is disabled |
| 403 "Compte désactivé : … documents suspects d'injection" (account disabled) | The account reached 10 injection attempts: an administrator must re-enable it |
| 429 "Trop de tentatives de connexion" (too many login attempts) | The login accumulated too many failures: wait for the end of the block (15 min by default) |
| All judge verdicts "unavailable" | Wrong `LLM_JUDGE_MODEL` (404/400), key refused (401/403) or too many calls (429) |
| `pip install` refused ("installed by the system") | Activate the virtual environment |

## 12. Report a problem

Give the route and body sent, the code and response received, the message in the uvicorn
terminal, and whether the LLM was on or off. Never paste a real document, a password, an API key
or the contents of `.env`.

The detailed documentation (judge, confidence, PII types, dashboard, measured results) is in
`anonymia/doc.txt`.