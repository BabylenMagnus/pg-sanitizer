"""Celery worker: runs the existing detector/generator/greenmask pipeline as one
async job, sequentially, via `docker compose run` — same commands as the manual
README workflow, just parameterized per-source and orchestrated instead of
typed by hand.

Runs on the host (not inside its own container) so it can shell out to
`docker compose` against the sibling services in ../docker-compose.yml
without Docker-outside-of-Docker socket/path-mapping issues. See api/README.md.

A source's `connection` JSON has two host/port pairs because the containers
(detector/generator/greenmask, on the compose network) and this worker
process (on the host) reach the same Postgres instance differently:
  container_host/container_port — what detector/generator/greenmask use
  api_host/api_port             — what this worker uses for the direct
                                   psycopg2 drop/create-database step
For a real external DSN source these are normally identical; for the
docker_local/upload sources (living inside playground-db) they differ
(playground-db:5432 from inside the compose network vs localhost:54316 from
the host).
"""
import json
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
from celery import Celery

from . import db

REDIS_URL = os.environ.get("JOBS_BROKER_URL", "redis://localhost:63790/1")
# Local dev: worker runs on the host, so this file's own location resolves
# to db-sanitization/ correctly. Containerized prod deploy: the image's
# internal layout doesn't match the host's, so PIPELINE_HOST_DIR must be set
# explicitly to the *host* path of db-sanitization/, bind-mounted into the
# worker container at that same path (sibling-container / Docker-socket
# requirement — see api/Dockerfile and docker-compose.yml `worker` service).
PIPELINE_DIR = Path(os.environ.get("PIPELINE_HOST_DIR", str(Path(__file__).resolve().parents[2])))

# Retention knobs for cleanup_target_databases — see its own docstring.
TARGET_RETENTION_HOURS = float(os.environ.get("TARGET_RETENTION_HOURS", "24"))
LOW_DISK_FREE_BYTES = int(float(os.environ.get("LOW_DISK_FREE_GB", "5")) * 1024**3)

celery_app = Celery("sanitizer_jobs", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(task_track_started=True)
celery_app.conf.beat_schedule = {
    "cleanup-target-databases": {
        "task": "cleanup_target_databases",
        # Frequent enough to react to disk pressure without over-polling —
        # this task's own work (a handful of DROP DATABASE calls at most) is
        # cheap regardless of how often it runs.
        "schedule": 900.0,
    },
}


def _step_start(job_id: str, step: str, timings: dict):
    """Marks a step as started: sets job status + records the start time in
    `timings`, immediately persisted so the frontend can show "running for
    Ns" for the in-progress step, not just completed ones."""
    started = datetime.now(timezone.utc)
    timings[step] = {"started_at": started.isoformat()}
    db.update_job(job_id, status=step, step_timings=json.dumps(timings))
    return started


def _step_end(job_id: str, step: str, timings: dict, started: datetime):
    finished = datetime.now(timezone.utc)
    timings[step]["finished_at"] = finished.isoformat()
    timings[step]["duration_seconds"] = round((finished - started).total_seconds(), 1)
    db.update_job(job_id, step_timings=json.dumps(timings))


def _heartbeat_loop(job_id: str, stop_event: threading.Event, interval: float = 10.0):
    """Runs in a background thread for the lifetime of a subprocess step,
    touching updated_at periodically. Needed because a silent long-running
    step (pg_dump against a large/remote database prints nothing until it's
    done) would otherwise leave updated_at frozen for minutes, which the
    frontend reads as "possibly stuck" even though the process is fine."""
    while not stop_event.wait(interval):
        db.touch_job(job_id)


def _stream_subprocess(job_id: str, cmd: list[str]) -> int:
    """Runs cmd, appending its combined stdout/stderr to the job's logs line
    by line as it's produced (buffered briefly, not one DB write per line)
    instead of blocking until the process exits and writing everything at
    once. A heartbeat thread keeps updated_at moving even during stretches
    with no output at all."""
    proc = subprocess.Popen(
        cmd, cwd=PIPELINE_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    stop_event = threading.Event()
    heartbeat = threading.Thread(
        target=_heartbeat_loop, args=(job_id, stop_event), daemon=True
    )
    heartbeat.start()

    buf: list[str] = []
    last_flush = time.monotonic()
    try:
        for line in proc.stdout:
            buf.append(line)
            now = time.monotonic()
            if now - last_flush >= 1.5:
                db.append_log(job_id, "".join(buf))
                buf.clear()
                last_flush = now
        if buf:
            db.append_log(job_id, "".join(buf))
    finally:
        stop_event.set()
        heartbeat.join(timeout=2)

    return proc.wait()


def _run(job_id: str, step: str, cmd: list[str], timings: dict):
    started = _step_start(job_id, step, timings)
    db.append_log(job_id, f"\n$ {' '.join(cmd)}\n")
    returncode = _stream_subprocess(job_id, cmd)
    _step_end(job_id, step, timings, started)
    if returncode != 0:
        raise RuntimeError(f"step '{step}' failed (exit {returncode}): {cmd}")


def _job_out_dir(job_id: str) -> str:
    """detector/generator/greenmask all mount the same named `detector-out`
    volume at /out — without a per-job subdirectory, two jobs running
    concurrently (the Celery worker has no --concurrency=1 limit) can
    clobber each other's report.json between one job's detecting and
    generating steps, silently feeding one source's findings into another
    source's generate/dump run."""
    return f"/out/{job_id}"


def _env_flags(conn: dict, job_id: str) -> list[str]:
    out_dir = _job_out_dir(job_id)
    flags = [
        "-e", f"DBHOST={conn['container_host']}",
        "-e", f"DBPORT={conn['container_port']}",
        "-e", f"DBUSER={conn['user']}",
        "-e", f"DBPASSWORD={conn['password']}",
        "-e", f"ORIGINAL_DB_NAME={conn['original_db']}",
        "-e", f"DETECTOR_OUT_DIR={out_dir}",
        "-e", f"DETECTOR_REPORT_PATH={out_dir}/report.json",
        "-e", f"DETECTED_TRANSFORMATION_PATH={out_dir}/transformation.detected.yml",
    ]
    return flags


def _target_env_flags(conn: dict) -> list[str]:
    """Env flags for the greenmask *restore* step only — points the
    container at conn's target_*, which is always OUR OWN playground-db,
    never the external server a dsn/upload source's original data lives on.
    Deliberately separate from _env_flags (DBHOST/etc.), which is always the
    *source* — conflating the two here was a real incident: a database was
    being created/dropped on a client's remote server (see main.py::
    create_dsn_source)."""
    return [
        "-e", f"TARGET_DBHOST={conn['target_container_host']}",
        "-e", f"TARGET_DBPORT={conn['target_container_port']}",
        "-e", f"TARGET_DBUSER={conn['target_user']}",
        "-e", f"TARGET_DBPASSWORD={conn['target_password']}",
    ]


def _recreate_target_db(conn: dict):
    """Drop/recreate the transformed DB via a direct connection from the
    worker (host) process — always against conn's target_* (our own
    playground-db), never conn's source api_host/api_port, which for a dsn
    source is the external server the original data lives on."""
    pg = psycopg2.connect(
        host=conn["target_api_host"], port=conn["target_api_port"], user=conn["target_user"],
        password=conn["target_password"], dbname="postgres",
    )
    pg.autocommit = True
    with pg.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{conn["transformed_db"]}"')
        cur.execute(f'CREATE DATABASE "{conn["transformed_db"]}"')
    pg.close()


@celery_app.task(name="run_sanitization_job")
def run_sanitization_job(job_id: str, source: dict):
    # Copy, don't mutate source["connection"] — and give *this job's* target
    # database a unique, job-scoped name. Without this, two concurrent jobs
    # against the same source (now possible — see worker --concurrency in
    # docker-compose.yml) would both drop/recreate/restore into the exact
    # same transformed_db and corrupt each other's run. Persisted on the job
    # row (target_db) so main.py's tables/preview/export endpoints know
    # which actual database this job's result lives in.
    conn = dict(source["connection"])
    conn["transformed_db"] = f"{conn['transformed_db']}_{job_id[:8]}"
    db.update_job(job_id, target_db=conn["transformed_db"])

    timings: dict = {}
    db.update_job(job_id, started_at=datetime.now(timezone.utc).isoformat())
    try:
        env_flags = _env_flags(conn, job_id)

        # --no-deps on every step: playground-db/mapping-store are long-running
        # services already brought up once by `docker compose up -d api worker`
        # (see deploy script) — without --no-deps, every single `docker compose
        # run` here makes Compose reconcile the full depends_on graph, which
        # was observed recreating (briefly stopping + healthcheck-waiting)
        # playground-db and mapping-store, and rerunning the one-shot
        # playground-dbs-filler job, on *every step of every job* — several
        # seconds of pure overhead, irrelevant for DSN/upload sources that
        # don't even touch playground-db. Step ordering is already enforced by
        # this function running each _run call sequentially, so Compose's own
        # depends_on ordering isn't needed here.
        _run(job_id, "detecting", ["docker", "compose", "run", "--rm", "--no-deps", *env_flags, "detector"], timings)
        _run(job_id, "generating", ["docker", "compose", "run", "--rm", "--no-deps", *env_flags, "generator"], timings)

        # "dumping" covers both the DB recreate and the greenmask dump itself —
        # start the timer before recreate_target_db rather than inside _run,
        # so the step's duration isn't understated.
        dumping_started = _step_start(job_id, "dumping", timings)
        db.append_log(job_id, f"\nrecreating target database '{conn['transformed_db']}'...\n")
        _recreate_target_db(conn)
        dump_cmd = [
            "docker", "compose", "run", "--rm", "--no-deps", *env_flags,
            "-e", f"TRANSFORMED_DB_NAME={conn['transformed_db']}",
            "greenmask", "dump", "--config=/var/lib/greenmask/config.generated.yml",
        ]
        db.append_log(job_id, f"\n$ {' '.join(dump_cmd)}\n")
        dump_returncode = _stream_subprocess(job_id, dump_cmd)
        _step_end(job_id, "dumping", timings, dumping_started)
        if dump_returncode != 0:
            raise RuntimeError(f"step 'dumping' failed (exit {dump_returncode}): {dump_cmd}")

        _run(
            job_id, "restoring",
            ["docker", "compose", "run", "--rm", "--no-deps", *env_flags, *_target_env_flags(conn),
             "-e", f"TRANSFORMED_DB_NAME={conn['transformed_db']}",
             "greenmask", "restore", "--config=/var/lib/greenmask/config.generated.yml", "latest"],
            timings,
        )

        # detector/out/report.json lives in the named `detector-out` Docker volume, not a
        # host bind mount — read it back out via a throwaway container instead of a host path.
        # Path is job-scoped (see _job_out_dir) so a concurrently running job's detector
        # can't have overwritten it by the time we get here.
        cat_proc = subprocess.run(
            ["docker", "compose", "run", "--rm", "--no-deps", "--entrypoint", "cat",
             "detector", f"{_job_out_dir(job_id)}/report.json"],
            cwd=PIPELINE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        report = json.loads(cat_proc.stdout) if cat_proc.returncode == 0 else []
        auto_applied = [f for f in report if f.get("auto_applied")]
        review_only = [f for f in report if not f.get("auto_applied")]
        result = {
            "source_label": source["label"],
            "auto_applied_count": len(auto_applied),
            "review_only_count": len(review_only),
            "findings": report,
        }
        db.update_job(
            job_id, status="done", result=json.dumps(result),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:  # noqa: BLE001 — surface any failure to the UI, not just RuntimeError
        db.update_job(
            job_id, status="error", error_message=str(exc),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )


def drop_target_db(conn: dict, target_db: str):
    """Drops one job's sanitized-copy database. Always against conn's
    target_* (our own playground-db) — same rule as _recreate_target_db.
    Connects to the admin "postgres" database, not target_db itself
    (Postgres can't drop a database you're currently connected to)."""
    pg = psycopg2.connect(
        host=conn["target_api_host"], port=conn["target_api_port"], user=conn["target_user"],
        password=conn["target_password"], dbname="postgres",
    )
    pg.autocommit = True
    try:
        with pg.cursor() as cur:
            cur.execute(f'DROP DATABASE IF EXISTS "{target_db}"')
    finally:
        pg.close()


@celery_app.task(name="cleanup_target_databases")
def cleanup_target_databases():
    """Two independent rules, both walking jobs oldest-first
    (db.list_jobs_with_live_target):

    1. Age: any job's target database older than TARGET_RETENTION_HOURS
       (default 24h / "старше одного дня") gets dropped, unconditionally.
    2. Disk pressure: if the host's free disk space is below
       LOW_DISK_FREE_GB (default 5), keep dropping the oldest remaining
       target databases (regardless of age) until free space recovers above
       the threshold or nothing is left to drop — a blunt but simple safety
       valve so the host doesn't fill up.

    Runs on a schedule (celery_app.conf.beat_schedule) via the separate
    `beat` service in docker-compose.yml — this task itself just needs the
    `worker` service (Celery beat only enqueues, doesn't execute)."""
    jobs = db.list_jobs_with_live_target()
    now = datetime.now(timezone.utc)
    age_cutoff = now - timedelta(hours=TARGET_RETENTION_HOURS)

    dropped = 0
    remaining = []
    for job in jobs:
        source = db.get_source(job["source_id"])
        if not source:
            continue  # source deleted out from under an old job — nothing to drop against
        created_at = job["created_at"]
        if created_at < age_cutoff:
            drop_target_db(source["connection"], job["target_db"])
            db.mark_target_deleted(job["id"])
            dropped += 1
        else:
            remaining.append(job)

    free_bytes = shutil.disk_usage(PIPELINE_DIR).free
    for job in remaining:  # already oldest-first
        if free_bytes >= LOW_DISK_FREE_BYTES:
            break
        source = db.get_source(job["source_id"])
        if not source:
            continue
        drop_target_db(source["connection"], job["target_db"])
        db.mark_target_deleted(job["id"])
        dropped += 1
        free_bytes = shutil.disk_usage(PIPELINE_DIR).free

    return {"dropped": dropped}
