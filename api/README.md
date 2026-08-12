# api — jobs service for db-sanitization

Turns the manual `docker compose run detector/generator/greenmask` sequence from the main
README into an async job driven by HTTP calls instead of typed by hand. Live in production
(guts, `docker compose up -d api worker`) — this is not a local-only demo.

The web UI (`sanitaizer-web`, a separate repository) is one client of this API — its
server-side route handlers validate a better-auth session and forward trusted internal
headers here. **This API has no UI of its own and no session/cookie auth** — every real
endpoint is driven entirely by the headers below, so everything in this README works without
`sanitaizer-web` at all (curl, a script, another frontend, whatever).

Runs on the **host** in local dev, or as a container (`worker` service in
`../docker-compose.yml`) in prod — either way it shells out to `docker compose` against the
sibling services in `../docker-compose.yml`, which avoids Docker-outside-of-Docker
socket/path-mapping issues (see the `worker` service's `/var/run/docker.sock` mount and
`PIPELINE_HOST_DIR`).

## Auth

No passwords, no sessions — every request needs three headers matching a trusted caller:

```
X-Internal-Secret: <JOBS_INTERNAL_SECRET>   # from .env / docker-compose.yml
X-User-Id: <any string>                     # attributed to jobs this call creates
X-User-Role: admin | user                   # "admin" required for DSN source registration
```

`JOBS_INTERNAL_SECRET` lives in `.env` (see `docker-compose.yml`'s `api`/`worker` services).
Anyone with that secret can drive the full API — treat it like a root credential, not
something to hand out per-user.

## Usage — full workflow via curl, no web UI

```bash
API=http://localhost:8020   # or http://localhost:8000 in local dev
SECRET=<JOBS_INTERNAL_SECRET>
AUTH=(-H "X-Internal-Secret: $SECRET" -H "X-User-Id: cli" -H "X-User-Role: admin")

# 1. List sources already registered
curl -s "$API/api/sources" "${AUTH[@]}"

# 2a. Register an external Postgres as a source (admin-only) — tested with a real
#     connection attempt before it's saved.
curl -s -X POST "$API/api/sources/dsn" "${AUTH[@]}" -H "Content-Type: application/json" -d '{
  "label": "customer prod", "host": "db.example.com", "port": "5432",
  "dbuser": "postgres", "password": "...", "dbname": "app"
}'
# -> {"source_id": "..."}

# 2b. ...or register a plain-SQL dump instead (pg_dump --format=plain, <=500MB) —
#     loaded into a fresh database inside our own playground-db.
curl -s -X POST "$API/api/sources/upload" "${AUTH[@]}" -F "label=my dump" -F "file=@dump.sql"
# -> {"source_id": "..."}

# 3. Start a job against any source_id from step 1/2
curl -s -X POST "$API/api/jobs/start" "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"source_id": "adventure_works_docker"}'
# -> {"job_id": "..."}

# 4. Poll status — moves through queued -> detecting -> generating -> dumping ->
#    restoring -> done (or error), with streamed logs and a findings result on completion.
curl -s "$API/api/jobs/<job_id>/status" "${AUTH[@]}"

# List all jobs (admin sees everyone's; a non-admin X-User-Id sees only its own)
curl -s "$API/api/jobs" "${AUTH[@]}"
```

`GET /api/jobs/latest` (any authenticated caller, not just the job's owner) returns the most
recently completed job across all users — this is what a public "latest report" page would
poll, no ownership check.

## Source vs. target — why they're different fields

A source's `connection` JSON has two independent halves:

- **Source** (`container_host`/`container_port`/`api_host`/`api_port`/`user`/`password`/
  `original_db`) — where the original data lives. For a `dsn` source this can be a
  third-party server; only ever read from (`SELECT`, `pg_dump` — both non-destructive).
- **Target** (`target_container_host`/`target_container_port`/`target_api_host`/
  `target_api_port`/`target_user`/`target_password`/`transformed_db`) — where the sanitized
  copy is created and restored. **Always our own `playground-db`**, regardless of source kind.

Conflating these was a real incident (2026-08-12): a `dsn` source's target used to reuse the
source's own host, so `_recreate_target_db`'s `DROP DATABASE`/`CREATE DATABASE` and
`greenmask restore` ran directly against a client's remote server. Fixed in `main.py`
(`create_dsn_source`/`create_upload_source`), `tasks.py` (`_recreate_target_db`,
`_target_env_flags`), and `docker/greenmask/merge_config.py` (dump reads `DBHOST`/etc.,
restore reads a separate `TARGET_DBHOST`/etc.) — see comments in those files. Any new source
kind must populate both halves explicitly; there's no fallback that silently reuses the
source host for the target.

## Run locally

```bash
cd db-sanitization/api
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate
pip install -r requirements.txt

# terminal 1 — API
uvicorn app.main:app --reload --port 8000

# terminal 2 — worker (needs `docker` on PATH, run from the same machine as docker compose)
celery -A app.tasks.celery_app worker --pool=solo --loglevel=info
```

Then use the curl workflow above against `http://localhost:8000`.

## What it actually does

One job = one sequential run of: `detector` → `generator` → drop/recreate the *target*
`transformed` DB → `greenmask dump` (reads source) → `greenmask restore` (writes target), via
`subprocess` calls to `docker compose run --no-deps` (see "Performance" below). Status and
streamed stdout/stderr land in a `jobs` table in a `jobs` database inside `playground-db`.
Each job writes detector's `report.json`/`transformation.detected.yml` to a job-scoped
`/out/<job_id>/` path inside the shared `detector-out` volume, and restores into a
job-scoped target database (`<transformed_db>_<job_id prefix>`, see `tasks.py::
run_sanitization_job`) — without both of these, two jobs running concurrently (see "Queueing
and concurrency" below) against the *same source* would clobber each other's detection
results and target database mid-run.

## Queueing and concurrency

Celery (backed by Redis, `JOBS_BROKER_URL`) is the queue — `POST /api/jobs/start` always
succeeds immediately and enqueues; a job sits at `status: "queued"` until a worker slot is
free, then moves through the normal `detecting → ... → done` sequence on its own. No separate
queueing system needed.

`docker-compose.yml`'s `worker` service sets `--concurrency=${WORKER_CONCURRENCY:-5}` —
how many jobs run *truly* in parallel on one worker process. Left unset, Celery defaults to
one process per CPU core (32 on guts), which for external DSN sources means up to 32
simultaneous full-database dumps competing for the same outbound network link — bounding it
is what makes "many people queue jobs, several run at once, the rest wait their turn"
actually safe instead of just eventually falling over. Tune `WORKER_CONCURRENCY` in `.env` if
guts' resources or typical source sizes change materially.

Known gap: each job's target database (see above) is never cleaned up after — they
accumulate in `playground-db` over time, one new database per completed job. Fine at current
volume, needs a retention/cleanup job (e.g. drop target_db for jobs older than N days) before
this runs at real 200-person scale for any length of time.

## Performance

- **`--no-deps` on every `docker compose run`** — without it, Compose reconciles the full
  `depends_on` graph on every single step of every job, which was observed briefly recreating
  `playground-db`/`mapping-store` and rerunning the one-shot `playground-dbs-filler` job each
  time — several seconds of pure overhead per step, irrelevant for DSN/upload sources that
  don't even touch `playground-db`. Step ordering is already enforced by `tasks.py` running
  each step sequentially, so Compose's own `depends_on` ordering isn't needed.
- **Streamed logs + heartbeat** — long-running steps (`greenmask dump`/`restore` against a
  large or high-latency remote source) stream output line-by-line instead of buffering until
  the step exits, and a background thread touches `updated_at` every 10s even when the
  process is silent, so a poller's "possibly stuck" heuristic doesn't false-positive on a
  step that's genuinely still running.
- `dump`/`restore` against an external DSN source are bound by that server's own network
  latency and data volume — not something this service can speed up further; `pg_dump`/
  `pg_restore` already run with `jobs: 4` (parallel workers) in `greenmask/config.template.yml`.

## Known limits

- **Step-level progress only**, not per-table — `status` moves through
  `detecting → generating → dumping → restoring → done`, with full stdout/stderr per step,
  not a live per-table progress bar. A finer-grained bar would need Greenmask to emit
  structured per-table events, which it doesn't today.
- **Redeploying `api`/`worker` mid-job orphans that job** — restarting the `worker` container
  kills its Celery process, but a `docker compose run` child it spawned (e.g. a long-running
  `greenmask dump`) keeps running detached; the job's row is left stuck at whatever status it
  was in, with no code left to ever mark it `done`/`error`. Not yet fixed — avoid deploying
  while jobs are in flight, or manually stop the orphaned container and update the job row
  after.
