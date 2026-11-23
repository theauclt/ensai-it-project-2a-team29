# Anonymia backend: developer guide

This document is for people who want to continue the development of the backend. To install and
run the application, see the `README.md` at the root of the repository.

Paths below are relative to the backend folder (the one that contains `pyproject.toml` and the
`anonymia/` package).

## 1. What the backend does

`POST /documents/caviarder` receives a text, detects the personal data (PII) in it with regular
expressions, an optional spaCy NER model and an LLM, then returns the text with the PII masked or
replaced by pseudonyms. Each processing is archived as an audit entry (hash of the document,
strategy, detectors, number and types of PII, injection verdicts), never the content itself.
Supervisors and administrators can read this history.

## 2. Layered architecture

The code is split into four layers. Each layer only knows the interfaces of the layer below it.

| Layer | Folder | Role |
|---|---|---|
| Presentation | `anonymia/presentation/` | FastAPI routes, Pydantic schemas, JWT security, `providers.py` (gives the routes their services) |
| Service | `anonymia/service/` | Business logic: `DetectionService`, `HistoryService`, `AuthentificationService`, `AdminService`; business objects (`PIISpan`, `AuditEntry`, `User`...); **interfaces** in `service/interfaces/` |
| Infrastructure | `anonymia/infrastructure/` | Concrete detectors (`RegexDetector`, `LLMDetector`, `SpacyDetector`), `LLMInjectionJudge`, strategies (`MaskingStrategy`, `PseudonymizationStrategy`) and their factory |
| Persistence | `anonymia/persistence/` | PostgreSQL access: `PostgresArchiveRepository`, `PostgresUserRepository`, connection pool in `dao/db_connexion.py` |

Other folders: `anonymia/data/` (database creation script), `anonymia/utils/`, `scripts/`
(command-line tools), `interface/` (Streamlit front end, which only calls the API), `tests/`.

### Dependency rule

- Routes only call services.
- Services depend on **abstract interfaces** (`PIIDetector`, `AnonymisationStrategy`,
  `ArchiveRepository`, `UserRepository`, `InjectionJudge`), never on a concrete class.
- Infrastructure and persistence **implement** these interfaces. The dependency is inverted: a
  service does not know whether the detector is a regex, spaCy or an LLM, nor whether the archive
  is PostgreSQL or a list in memory (this is what the tests use).

### Composition root

`anonymia/dependencies.py` is the only place that knows the concrete classes. Its `build_*`
functions create the detectors, the LLM client, the judge, the connection pool and the services.
`anonymia/main.py` calls them in the `lifespan` function (open the pool, build the services, store
them in `app.state`, close everything at shutdown). Routes get their service through
`presentation/providers.py`.

### Request flow (`DetectionService.detect`)

1. Get the strategy from the factory (an unknown name fails immediately).
2. Prompt-injection filter (pattern list). If an injection is suspected and the user has not
   confirmed, return `confirmation_requise` without processing or archiving anything.
3. Run the detectors **and** the LLM injection judge in parallel with `asyncio.gather`. A failing
   detector is dropped (degraded mode) and a failing judge gives the verdict `unavailable`: the
   processing goes on.
4. Merge the spans: the highest confidence wins, then the earliest start, then the longest.
5. Apply the strategy (synchronous, in memory).
6. Archive the `AuditEntry`, then return the result. Anonymisation and archiving are sequential on
   purpose: an audit line must never exist for a result the user did not receive.

`DetectionService.analyse` (route `POST /documents/analyser`) follows the same path (steps 1 to 4, then the
archive with the strategy `analyse`) but returns the detected spans instead of a redacted text. A suspect
document is blocked until it is confirmed, exactly as for `detect`.

The response carries `mode_degrade` (true when the LLM detector did not answer) and the list of
detectors that contributed.

### Asynchronous code

The application is asynchronous end to end. The database layer uses `psycopg` 3 with an
`AsyncConnectionPool` (1 to 5 connections, built by `construire_pool()`, opened in `lifespan`).
Repository methods are `async` and use `async with pool.connection()`: the transaction is
committed when the block ends, or rolled back if an exception occurs. Scripts such as `init_db`
use an ordinary connection (`connexion_synchrone()`). The LLM is reached through a shared
`httpx.AsyncClient`.

## 3. How to extend the application

**Add a detector.** Write a class in `infrastructure/` that implements `PIIDetector`
(`async def detect(self, content) -> list[PIISpan]`), then add it to the `detectors` list in
`build_detection_service` (`dependencies.py`). `DetectionService` does not change. This is how the
spaCy detector was added.

**Add an anonymisation strategy.** Implement `AnonymisationStrategy.apply(content, spans)` in
`infrastructure/`, register the class in `AnonymizationStrategyFactory`, and handle every PII type
(raise `ValueError` for an unsupported one). It then appears in `GET /documents/strategies`.

**Change the database.** Write two classes implementing `ArchiveRepository` and `UserRepository`
and return them from `build_archive_repository` / `build_user_repository`.

**Add a route.** Create it in `presentation/`, get the service through a function in
`providers.py`, and protect it with the role check from `security.py`. Business rules (for example
who may read the history) belong in the service, not in the route.

## 4. Database

`python -m anonymia.data.init_db` creates the `users` and `traitements` tables. It can be run
again at any time: it uses `CREATE TABLE IF NOT EXISTS` then `ALTER TABLE ... ADD COLUMN IF NOT
EXISTS`, so new columns are added without deleting anything. Run it after every `git pull` that
changes the schema.

- `users`: id, username (unique), password hash (bcrypt), role, active flag, creation date.
- `traitements`: one audit line per processing. `user_id` is nullable with `ON DELETE SET NULL`:
  deleting an account keeps its history.
- Dates are `TIMESTAMP` without time zone, stored as UTC (the session is set to UTC).

## 5. Development tools

### Tests

    pytest                                                  # all tests
    pytest tests/service                                    # one layer
    pytest --cov=anonymia --cov-branch --cov-report=term-missing

The tests need neither a real database nor a real LLM:

- `tests/fakes.py` provides in-memory repositories and fake detectors;
- the LLM is simulated with `httpx.MockTransport`;
- the tests mirror the layers: `tests/service`, `tests/infrastructure`, `tests/presentation` (API
  through FastAPI's test client), `tests/interface` (dashboard computations).

Services are tested through their interfaces with fakes, which is possible because of the
dependency rule above. Coverage is measured on the `anonymia` package.

### Code quality

    ruff check .

Run `ruff check .` and `pytest` before every commit: both must pass.

### Logs

Modules use the standard `logging` module (`logger = logging.getLogger(__name__)`). Warnings are
emitted when a detector or the judge is unavailable (degraded mode). **Only the type of the error
is logged, never the content of a document.** Keep this rule for any new log message.

### Evaluation scripts

    python -m scripts.evaluer_corpus corpus-test            # regex + injection filter
    python -m scripts.evaluer_corpus corpus-test --llm      # with the LLM
    python -m scripts.evaluer_juge corpus-test              # LLM injection judge

They compare the pipeline with a ground-truth grid (precision, recall, F1 by type) and write
`metriques.md` and `.csv` files for the report. `evaluer_corpus` also saves figures (confusion matrix,
precision/recall by type, recall by circle and by length, injection filter by attack family) in
`graphiques/`; this needs `matplotlib` (`pip install matplotlib`). They use no database. Other scripts:
`scripts.create_user` (create an account) and `scripts.check_db` (check database and login).

### Measuring time

`python mesurer_temps.py --llm` measures the detection time of the regex detector and of the LLM
(with a quick probe first, to separate network problems from slow generation).

## 6. Environment variables

The full table is in the root `README.md`. The ones that change the backend behaviour:

| Variable | Effect |
|---|---|
| `LLM_ENABLED=false` | No LLM detector and no judge (regex only) |
| `LLM_JUDGE_ENABLED=false` | No judge (it doubles the LLM calls) |
| `LLM_TIMEOUT` | Seconds to wait for the LLM (60 by default); on timeout the detector is dropped |
| `NER_ENABLED=true` | Add the spaCy detector (needs the model, loaded once at startup) |
| `JWT_SECRET` | At least 32 characters, otherwise the API refuses to start |

## 7. Known limits and ideas

- The history is filtered by date **in memory** (`HistoryService`), not in SQL. Fine for a few
  thousand lines; for more, add the date filter to the SQL query and an index on `date_traitement`.
- There is no index besides primary keys and the unique `username`.
- `types_pii` and `detectors` are stored as text (`EMAIL:2,NOM:1`), which is simple but not
  normalised. A child table `(traitement_id, type, count)` would allow SQL statistics.
- The prompt-injection filter and the LLM judge are signals, not barriers: they only cover known
  formulations and the judge itself reads the untrusted document.
- JWT tokens last 30 minutes and cannot be revoked: a disabled account keeps its access until the
  token expires.
- Not implemented: direct anonymisation by the LLM (FO2).