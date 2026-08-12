"""Storage for the jobs service: the `jobs` database inside the same
Postgres instance already used by the pipeline (playground-db). Two tables
here — `sources` (registry of what a job can run against) and `jobs` (run
history/status). Identity/roles live in better-auth's own tables (`user`,
`session` — see sanitaizer-web/src/lib/db/schema.ts, same database), so
`sources.created_by` / `jobs.user_id` are plain TEXT referencing
better-auth's `user.id` (a nanoid, not a UUID) rather than anything owned
here. Plain psycopg2, no ORM/migrations framework — scope doesn't need it.
"""
import json
import os
import uuid
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

DBHOST = os.environ.get("JOBS_DBHOST", "localhost")
DBPORT = os.environ.get("JOBS_DBPORT", "54316")
DBUSER = os.environ.get("JOBS_DBUSER", "postgres")
DBPASSWORD = os.environ.get("JOBS_DBPASSWORD", "example")
DBNAME = os.environ.get("JOBS_DBNAME", "jobs")


def _connect(dbname):
    return psycopg2.connect(
        host=DBHOST, port=DBPORT, user=DBUSER, password=DBPASSWORD, dbname=dbname
    )


@contextmanager
def get_conn():
    conn = _connect(DBNAME)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def ensure_database():
    conn = _connect("postgres")
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DBNAME,))
        if not cur.fetchone():
            cur.execute(f'CREATE DATABASE "{DBNAME}"')
    conn.close()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    id UUID PRIMARY KEY,
                    slug TEXT UNIQUE NOT NULL,
                    label TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('docker_local', 'dsn', 'upload')),
                    connection JSONB NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'ready',
                    allowed_roles TEXT[] NOT NULL DEFAULT ARRAY['admin', 'user'],
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id UUID PRIMARY KEY,
                    source_id UUID NOT NULL REFERENCES sources(id),
                    user_id TEXT,
                    status TEXT NOT NULL DEFAULT 'queued',
                    logs TEXT NOT NULL DEFAULT '',
                    error_message TEXT,
                    result JSONB,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );

                ALTER TABLE jobs ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
                ALTER TABLE jobs ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ;
                ALTER TABLE jobs ADD COLUMN IF NOT EXISTS step_timings JSONB NOT NULL DEFAULT '{}'::jsonb;
                -- Job-scoped target database name (e.g. "transformed_a1b2c3d4"),
                -- set once by tasks.py at job start. Without this, two
                -- concurrent jobs against the *same* source (now possible —
                -- see worker --concurrency in docker-compose.yml) would both
                -- write to the same fixed transformed_db and race each
                -- other's DROP/CREATE DATABASE + restore.
                ALTER TABLE jobs ADD COLUMN IF NOT EXISTS target_db TEXT;
                -- Set once the job's sanitized copy has been dropped (by the
                -- user via DELETE /api/jobs/{id}/target, or automatically by
                -- tasks.py's cleanup_target_databases) — the job row and its
                -- logs/findings stay around, only the actual data is gone.
                ALTER TABLE jobs ADD COLUMN IF NOT EXISTS target_deleted_at TIMESTAMPTZ;
                """
            )
            cur.execute("SELECT count(*) FROM sources")
            (count,) = cur.fetchone()
            if count == 0:
                cur.execute(
                    """INSERT INTO sources (id, slug, label, kind, connection, allowed_roles)
                       VALUES (%s, 'adventure_works_docker',
                               'Adventure Works (local Docker playground)', 'docker_local',
                               %s, ARRAY['admin','user'])""",
                    (
                        str(uuid.uuid4()),
                        json.dumps(
                            {
                                "container_host": "playground-db", "container_port": "5432",
                                # DBHOST/DBPORT, not a hardcoded "localhost" — this process
                                # (API/worker) already proved it can reach Postgres at
                                # DBHOST:DBPORT (see ensure_database() above), which is
                                # "localhost:54316" when the worker runs on the host (local
                                # dev) but "playground-db:5432" when it runs as a container
                                # on the compose network (prod). Hardcoding "localhost" here
                                # broke the containerized worker's own direct psycopg2
                                # connection in tasks.py::_recreate_target_db.
                                "api_host": DBHOST, "api_port": DBPORT,
                                "user": "postgres", "password": "example",
                                "original_db": "original", "transformed_db": "transformed",
                                # Already our own playground-db for both source and
                                # target — mirrors source fields for consistency with
                                # the dsn source kind, which needs them to actually
                                # differ (see main.py::create_dsn_source).
                                "target_container_host": "playground-db", "target_container_port": "5432",
                                "target_api_host": DBHOST, "target_api_port": DBPORT,
                                "target_user": "postgres", "target_password": "example",
                            }
                        ),
                    ),
                )


# ---- sources ----

def list_sources(role: str):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM sources WHERE %s = ANY(allowed_roles) ORDER BY created_at", (role,)
            )
            return cur.fetchall()


def get_source(source_id: str):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM sources WHERE id = %s", (source_id,))
            return cur.fetchone()


def create_source(slug, label, kind, connection: dict, allowed_roles, created_by, status="ready") -> str:
    source_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sources (id, slug, label, kind, connection, status, allowed_roles, created_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (source_id, slug, label, kind, json.dumps(connection), status, allowed_roles, created_by),
            )
    return source_id


def update_source_status(source_id: str, status: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE sources SET status = %s WHERE id = %s", (status, source_id))


# ---- jobs ----

def create_job(source_id: str, user_id: str | None) -> str:
    job_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jobs (id, source_id, user_id, status) VALUES (%s, %s, %s, 'queued')",
                (job_id, source_id, user_id),
            )
    return job_id


def update_job(job_id: str, **fields):
    if not fields:
        return
    set_clauses = ["updated_at = now()"]
    values = []
    for key, value in fields.items():
        set_clauses.append(f"{key} = %s")
        values.append(value)
    values.append(job_id)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE jobs SET {', '.join(set_clauses)} WHERE id = %s", values)


def touch_job(job_id: str):
    """Bumps updated_at with no other change — a liveness heartbeat for
    long-running steps (e.g. pg_dump against a large remote database) that
    produce no stdout for minutes at a time, so the frontend's "possibly
    stuck" heuristic (based on time since updated_at) doesn't false-positive
    on a step that's actually still running."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE jobs SET updated_at = now() WHERE id = %s", (job_id,))


def append_log(job_id: str, text: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE jobs SET logs = logs || %s, updated_at = now() WHERE id = %s",
                (text, job_id),
            )


def mark_target_deleted(job_id: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE jobs SET target_deleted_at = now(), updated_at = now() WHERE id = %s",
                (job_id,),
            )


def list_jobs_with_live_target(limit: int = 500):
    """Jobs whose sanitized copy still exists (target_db set, not yet
    deleted), oldest first — what tasks.py's cleanup_target_databases walks
    through for both the 1-day age rule and the low-disk-space rule."""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM jobs WHERE target_db IS NOT NULL AND target_deleted_at IS NULL "
                "ORDER BY created_at ASC LIMIT %s",
                (limit,),
            )
            return cur.fetchall()


def get_latest_done_job():
    """Most recent successfully completed job across all users — backs the
    public `/report` page on sanitaizer-web, which shows the latest real
    pipeline run rather than a build-time-baked snapshot."""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM jobs WHERE status = 'done' ORDER BY created_at DESC LIMIT 1"
            )
            return cur.fetchone()


def get_job(job_id: str):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
            return cur.fetchone()


def list_jobs(user_id: str | None, is_admin: bool, limit: int = 50):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if is_admin:
                cur.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT %s", (limit,))
            else:
                cur.execute(
                    "SELECT * FROM jobs WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
                    (user_id, limit),
                )
            return cur.fetchall()
