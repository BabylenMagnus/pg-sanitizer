"""Lookup-service: Greenmask's Cmd transformer calls this as a persistent
process, one instance per configured table, connected over stdin/stdout with
the built-in `json` driver (see docs/built_in_transformers/standard_transformers/cmd.md
in the greenmask clone). Invoked with --schema/--table so the same script can
serve every table without cross-table key collisions.

Read-mostly by design: generator/ (task 5) pre-populates every mapping this
run will need in the mapping store *before* Greenmask starts dumping. That is
what makes this process safe under Greenmask's parallel dump (-j): every
worker only ever GETs a key that already exists, so there is no read-modify-write
race between concurrent table dumps to reason about. The on-the-fly fallback
below only fires if the detector/generator missed a value (schema drift,
bug) -- it is a defensive last resort, not the primary path, and it is safe
precisely because it never needs cross-process coordination: a missed value
gets its own deterministic hash-based placeholder independently in each
worker, and HMAC(salt, value) is identical no matter which worker computes it,
so even two workers racing on the same never-seen value converge on the same
placeholder and the same Redis write (last write wins, same value).
"""
import argparse
import hashlib
import hmac
import json
import os
import signal
import sys

import psycopg2
import redis

signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))

REDIS_URL = os.environ.get("MAPPING_STORE_URL", "redis://localhost:6379/0")
SALT = os.environ.get("MAPPING_SALT", "").encode("utf-8")

_redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def load_column_max_lengths(schema: str, table: str) -> dict:
    """Any replacement -- cache hit, generator output, or the on-the-fly
    fallback -- must still fit the real column, whatever produced it. A
    fallback placeholder like `REDACTED-accountnumber-<hash>` is longer than
    several of Adventure Works' narrow varchar columns (e.g. accountnumber
    varchar(15)), and an LLM/Faker value can just as easily overshoot a
    narrow column (passwordsalt varchar(10)) -- so this is enforced centrally
    here rather than trusted to whoever generated the value."""
    dsn = (
        f"host={os.environ.get('DBHOST', 'playground-db')} "
        f"port={os.environ.get('DBPORT', '5432')} "
        f"user={os.environ.get('DBUSER', 'postgres')} "
        f"password={os.environ.get('DBPASSWORD', 'example')} "
        f"dbname={os.environ.get('ORIGINAL_DB_NAME', 'original')}"
    )
    try:
        conn = psycopg2.connect(dsn)
        conn.set_session(readonly=True, autocommit=True)
        with conn.cursor() as cur:
            cur.execute(
                """
                select column_name, character_maximum_length
                from information_schema.columns
                where table_schema = %s and table_name = %s
                  and character_maximum_length is not null
                """,
                (schema, table),
            )
            return {row[0]: row[1] for row in cur.fetchall()}
    except Exception as exc:  # noqa: BLE001 -- degrade to no length enforcement rather than crash
        print(f"lookup-service: could not load column lengths ({exc}), skipping truncation", file=sys.stderr)
        return {}


def clamp(value: str, max_length: int | None) -> str:
    if max_length is not None and len(value) > max_length:
        return value[:max_length]
    return value

# businessentityid links firstname/middlename/lastname (person.person) and
# emailaddress (person.emailaddress) across tables -- passed through
# unmodified as context, see detector/detect.py IDENTITY_KEY_COLUMN.
IDENTITY_KEY_COLUMN = "businessentityid"
IDENTITY_COLUMNS = {"firstname", "middlename", "lastname", "emailaddress"}


def mapping_key(schema: str, table: str, column: str, original_value: str) -> str:
    digest = hmac.new(SALT, original_value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"mapping:{schema}.{table}.{column}:{digest}"


def identity_key(businessentityid: str) -> str:
    return f"identity:{businessentityid}"


def placeholder_for(schema: str, table: str, column: str, original_value: str) -> str:
    """Defensive fallback -- see module docstring. Should not fire on a
    correctly pre-populated store; a warning is logged to stderr when it does
    so a missed column shows up in `docker compose logs greenmask`."""
    digest = hmac.new(SALT, original_value.encode("utf-8"), hashlib.sha256).hexdigest()
    print(
        f"lookup-service: cache miss for {schema}.{table}.{column}, "
        f"falling back to placeholder (generator did not pre-populate this value)",
        file=sys.stderr,
    )
    return f"REDACTED-{column}-{digest[:8]}"


def resolve_value(schema: str, table: str, column: str, original_value: str, max_lengths: dict) -> str:
    key = mapping_key(schema, table, column, original_value)
    cached = _redis.get(key)
    if cached is None:
        cached = placeholder_for(schema, table, column, original_value)
        _redis.set(key, cached)
    return clamp(cached, max_lengths.get(column))


def resolve_identity(schema: str, table: str, businessentityid: str, record: dict, max_lengths: dict) -> None:
    """Fills every identity-linked column present in `record` from the shared
    identity bundle for this businessentityid, falling back per-field to the
    generic value-hash path if the bundle (or a field in it) is missing."""
    bundle = _redis.hgetall(identity_key(businessentityid))
    for column, cell in record.items():
        if column.lower() not in IDENTITY_COLUMNS or cell.get("n"):
            continue
        replacement = bundle.get(column.lower())
        if replacement is None:
            replacement = resolve_value(schema, table, column, cell["d"], max_lengths)
        cell["d"] = clamp(replacement, max_lengths.get(column))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", default="")
    parser.add_argument("--table", default="")
    args = parser.parse_args()

    max_lengths = load_column_max_lengths(args.schema, args.table)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)

        identity_cell = record.get(IDENTITY_KEY_COLUMN)
        if identity_cell is not None and not identity_cell.get("n"):
            resolve_identity(args.schema, args.table, identity_cell["d"], record, max_lengths)

        for column, cell in record.items():
            if column == IDENTITY_KEY_COLUMN or column.lower() in IDENTITY_COLUMNS:
                continue
            if cell.get("n"):
                continue
            cell["d"] = resolve_value(args.schema, args.table, column, cell["d"], max_lengths)

        sys.stdout.write(json.dumps(record))
        sys.stdout.write("\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
