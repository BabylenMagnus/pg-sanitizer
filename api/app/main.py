import io
import uuid

import psycopg2
import psycopg2.extras
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import db
from .auth import require_admin_caller, require_internal_caller
from .tasks import drop_target_db, run_sanitization_job

app = FastAPI(title="db-sanitization jobs API")

# Only sanitaizer-web's own server-side route handlers call this API (see
# api/README.md) — the browser never talks to it directly, so this is not a
# public CORS surface, just enough to let local `next dev` reach it too.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3099", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    db.ensure_database()


# ---- sources ----

@app.get("/api/sources")
def list_sources(user=Depends(require_internal_caller)):
    return db.list_sources(user["role"])


class CreateDsnSourceRequest(BaseModel):
    label: str
    host: str
    port: str = "5432"
    dbuser: str = "postgres"
    password: str
    dbname: str


@app.post("/api/sources/dsn")
def create_dsn_source(req: CreateDsnSourceRequest, user=Depends(require_admin_caller)):
    """Registers an external Postgres as a source. Admin-only: this is
    exactly the credential a platform team hands out carefully, not
    something 200 regular users type into a form (see the guardrails
    discussion this feature is built from)."""
    try:
        test_conn = psycopg2.connect(
            host=req.host, port=req.port, user=req.dbuser, password=req.password,
            dbname=req.dbname, connect_timeout=5,
        )
        test_conn.close()
    except psycopg2.OperationalError as exc:
        raise HTTPException(400, f"could not connect to database: {exc}")

    slug = f"dsn-{uuid.uuid4().hex[:8]}"
    connection = {
        "container_host": req.host, "container_port": req.port,
        "api_host": req.host, "api_port": req.port,
        "user": req.dbuser, "password": req.password,
        "original_db": req.dbname, "transformed_db": f"{req.dbname}_sanitized",
        # Target (where the sanitized copy is created/restored) is always
        # OUR OWN playground-db — NEVER the external server the original
        # lives on. detector/generator/greenmask-dump only ever read from
        # container_host/api_host above (SELECT / pg_dump, non-destructive);
        # the only writes (CREATE/DROP DATABASE, pg_restore) go here instead.
        # See project_wiki/wiki/deployment.md — this was a real incident
        # (2026-08-12): a "postgres_sanitized" database was being created on
        # a client's remote Supabase instance and had to be cleaned up.
        "target_container_host": "playground-db", "target_container_port": "5432",
        "target_api_host": db.DBHOST, "target_api_port": db.DBPORT,
        "target_user": "postgres", "target_password": "example",
    }
    source_id = db.create_source(
        slug, req.label, "dsn", connection, ["admin", "user"], user["id"],
    )
    return {"source_id": source_id}


@app.post("/api/sources/upload")
async def create_upload_source(
    label: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(require_internal_caller),
):
    """Accepts a plain-SQL dump (`.sql`, produced by `pg_dump --format=plain`),
    loads it into a fresh database inside the same Postgres instance the
    pipeline already uses, and registers it as a source. Deliberately
    plain-SQL only, not custom-format `.dump` — that would need `pg_restore`
    wired through the same container, which is a bigger change than this
    pass covers (see api/README.md, known limits)."""
    MAX_BYTES = 500 * 1024 * 1024
    contents = await file.read(MAX_BYTES + 1)
    if len(contents) > MAX_BYTES:
        raise HTTPException(400, "file too large — 500 MB limit")

    slug = f"upload-{uuid.uuid4().hex[:8]}"
    original_db = f"upload_{slug.replace('-', '_')}"
    transformed_db = f"{original_db}_sanitized"

    # db.DBHOST/DBPORT — not hardcoded "localhost" — is however this process
    # itself already reaches Postgres (localhost:54316 on the host in local
    # dev, playground-db:5432 from inside the compose network in prod).
    pg = psycopg2.connect(
        host=db.DBHOST, port=db.DBPORT, user="postgres", password="example", dbname="postgres",
    )
    pg.autocommit = True
    with pg.cursor() as cur:
        cur.execute(f'CREATE DATABASE "{original_db}"')
    pg.close()

    load_conn = psycopg2.connect(
        host=db.DBHOST, port=db.DBPORT, user="postgres", password="example", dbname=original_db,
    )
    load_conn.autocommit = True
    try:
        with load_conn.cursor() as cur:
            cur.execute(contents.decode("utf-8", errors="replace"))
    except Exception as exc:
        raise HTTPException(400, f"failed to load dump: {exc}")
    finally:
        load_conn.close()

    connection = {
        "container_host": "playground-db", "container_port": "5432",
        "api_host": db.DBHOST, "api_port": db.DBPORT,
        "user": "postgres", "password": "example",
        "original_db": original_db, "transformed_db": transformed_db,
        # Already our own playground-db for both source and target (the
        # uploaded dump was loaded here above) — target_* mirrors the
        # source fields for consistency with the dsn source kind, which
        # needs them to actually differ (see create_dsn_source).
        "target_container_host": "playground-db", "target_container_port": "5432",
        "target_api_host": db.DBHOST, "target_api_port": db.DBPORT,
        "target_user": "postgres", "target_password": "example",
    }
    source_id = db.create_source(slug, label, "upload", connection, ["admin", "user"], user["id"])
    return {"source_id": source_id}


# ---- jobs ----

class StartJobRequest(BaseModel):
    source_id: str


@app.post("/api/jobs/start")
def start_job(req: StartJobRequest, user=Depends(require_internal_caller)):
    source = db.get_source(req.source_id)
    if not source:
        raise HTTPException(404, "source not found")
    if user["role"] not in source["allowed_roles"]:
        raise HTTPException(403, "not allowed to use this source")
    job_id = db.create_job(req.source_id, user["id"])
    run_sanitization_job.delay(job_id, {"label": source["label"], "connection": source["connection"]})
    return {"job_id": job_id}


@app.get("/api/jobs")
def list_jobs(user=Depends(require_internal_caller)):
    return db.list_jobs(user["id"], user["role"] == "admin")


@app.get("/api/jobs/latest")
def latest_done_job(user=Depends(require_internal_caller)):
    """Latest successfully completed job across all users — not scoped to
    the caller. Backs the public `/report` page, which intentionally shows
    the most recent real run to anyone, not just its owner."""
    job = db.get_latest_done_job()
    if not job:
        raise HTTPException(404, "no completed jobs yet")
    return job


@app.get("/api/jobs/{job_id}/status")
def job_status(job_id: str, user=Depends(require_internal_caller)):
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    if user["role"] != "admin" and job["user_id"] != user["id"]:
        raise HTTPException(403, "not your job")
    return job


# ---- table browsing / export (post-completion, for a finished job) ----
# All three endpoints below read the *target* connection (our own
# playground-db) for anything they write-adjacent (row counts, CSV export),
# and additionally the *source* connection (read-only) for preview's
# "original" side — see README.md "Безопасность: куда физически пишутся
# данные" for why these two are never the same connection for a dsn source.

def _job_and_source(job_id: str, user: dict):
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    if user["role"] != "admin" and job["user_id"] != user["id"]:
        raise HTTPException(403, "not your job")
    if job["status"] != "done":
        raise HTTPException(409, "job hasn't finished yet")
    if job.get("target_deleted_at"):
        raise HTTPException(410, "sanitized data for this job has been deleted")
    source = db.get_source(job["source_id"])
    if not source:
        raise HTTPException(404, "source not found")
    return job, source


@app.delete("/api/jobs/{job_id}/target")
def delete_job_target(job_id: str, user=Depends(require_internal_caller)):
    """Manually drops a job's sanitized-copy database on request (e.g. right
    after the user has exported what they needed) — same drop path
    (`tasks.drop_target_db`) automatic cleanup uses, just triggered
    on-demand instead of by age/disk pressure."""
    job, source = _job_and_source(job_id, user)
    drop_target_db(source["connection"], job["target_db"])
    db.mark_target_deleted(job_id)
    return {"deleted": True}


def _job_target_db(job: dict, conn: dict) -> str:
    """The database this specific job actually wrote its sanitized copy
    into — job-scoped (see tasks.py::run_sanitization_job) since concurrent
    jobs against the same source no longer share one fixed transformed_db.
    Falls back to the source's generic transformed_db for jobs that ran
    before this column existed."""
    return job.get("target_db") or conn["transformed_db"]


def _pg_connect(host, port, dbuser, password, dbname):
    return psycopg2.connect(
        host=host, port=port, user=dbuser, password=password, dbname=dbname, connect_timeout=10,
    )


def _split_table(table: str) -> tuple[str, str]:
    if "." not in table:
        raise HTTPException(400, "table must be 'schema.table'")
    schema, table_name = table.split(".", 1)
    return schema, table_name


def _validate_table(pg, schema: str, table_name: str):
    """schema/table_name end up interpolated into SQL identifiers below
    (psycopg2 can't parameterize identifiers) — confirming they're a real
    table via a parameterized information_schema lookup first is what makes
    that safe, not string-sanitizing them by hand."""
    with pg.cursor() as cur:
        cur.execute(
            "select 1 from information_schema.tables "
            "where table_schema = %s and table_name = %s and table_type = 'BASE TABLE'",
            (schema, table_name),
        )
        if not cur.fetchone():
            raise HTTPException(404, "table not found")


@app.get("/api/jobs/{job_id}/tables")
def job_tables(job_id: str, user=Depends(require_internal_caller)):
    """Every table in the job's sanitized (target) database, with row count
    and whether detector flagged it as containing PII that got auto-applied
    — lets the UI distinguish "changed" from "untouched" tables instead of
    only showing the handful of PII-bearing ones."""
    job, source = _job_and_source(job_id, user)
    conn = source["connection"]
    findings = (job["result"] or {}).get("findings", []) if job["result"] else []
    changed_tables = {(f["schema"], f["table"]) for f in findings if f.get("auto_applied")}

    pg = _pg_connect(
        conn["target_api_host"], conn["target_api_port"],
        conn["target_user"], conn["target_password"], _job_target_db(job, conn),
    )
    try:
        with pg.cursor() as cur:
            cur.execute(
                "select table_schema, table_name from information_schema.tables "
                "where table_schema not in ('pg_catalog', 'information_schema') "
                "and table_type = 'BASE TABLE' order by table_schema, table_name"
            )
            rows = cur.fetchall()
        tables = []
        for schema, table_name in rows:
            with pg.cursor() as cur:
                cur.execute(f'select count(*) from "{schema}"."{table_name}"')
                (row_count,) = cur.fetchone()
            tables.append({
                "schema": schema, "table": table_name, "row_count": row_count,
                "changed": (schema, table_name) in changed_tables,
            })
        return tables
    finally:
        pg.close()


@app.get("/api/jobs/{job_id}/preview")
def job_preview(job_id: str, table: str, limit: int = 20, user=Depends(require_internal_caller)):
    """Original vs. sanitized rows for one table, ordered by its first
    column (in practice the primary key, which the transformer never
    touches — see README.md "Что сознательно не делаем") so row N on one
    side is the same logical row as row N on the other."""
    job, source = _job_and_source(job_id, user)
    conn = source["connection"]
    schema, table_name = _split_table(table)
    limit = max(1, min(limit, 200))

    target_pg = _pg_connect(
        conn["target_api_host"], conn["target_api_port"],
        conn["target_user"], conn["target_password"], _job_target_db(job, conn),
    )
    try:
        _validate_table(target_pg, schema, table_name)
        with target_pg.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f'select * from "{schema}"."{table_name}" order by 1 limit %s', (limit,))
            transformed_rows = [dict(r) for r in cur.fetchall()]
    finally:
        target_pg.close()

    source_pg = _pg_connect(
        conn["api_host"], conn["api_port"], conn["user"], conn["password"], conn["original_db"],
    )
    try:
        with source_pg.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f'select * from "{schema}"."{table_name}" order by 1 limit %s', (limit,))
            original_rows = [dict(r) for r in cur.fetchall()]
    finally:
        source_pg.close()

    columns = list(transformed_rows[0].keys()) if transformed_rows else (
        list(original_rows[0].keys()) if original_rows else []
    )
    return {"columns": columns, "original_rows": original_rows, "transformed_rows": transformed_rows}


@app.get("/api/jobs/{job_id}/export")
def job_export(job_id: str, table: str, user=Depends(require_internal_caller)):
    """Streams one table from the job's *sanitized* (target) database as
    CSV — never the original. Buffers the whole CSV in memory via
    `copy_expert`, which is fine at this project's demo scale; a genuinely
    huge table would need a real streaming generator instead."""
    job, source = _job_and_source(job_id, user)
    conn = source["connection"]
    schema, table_name = _split_table(table)

    pg = _pg_connect(
        conn["target_api_host"], conn["target_api_port"],
        conn["target_user"], conn["target_password"], _job_target_db(job, conn),
    )
    try:
        _validate_table(pg, schema, table_name)
        buf = io.StringIO()
        with pg.cursor() as cur:
            cur.copy_expert(f'copy "{schema}"."{table_name}" to stdout with csv header', buf)
    finally:
        pg.close()

    buf.seek(0)
    filename = f"{schema}_{table_name}_sanitized.csv"
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
