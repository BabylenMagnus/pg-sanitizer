"""Merges the static Greenmask config template with the transformation
fragment produced by detector/ into the final config Greenmask actually runs
with. Kept separate from detect.py: the detector knows PII columns, not
Greenmask's connection/storage settings, and vice versa.
"""
import os
import sys

import yaml

TEMPLATE_PATH = os.environ.get("GREENMASK_CONFIG_TEMPLATE", "/var/lib/greenmask/config/config.template.yml")
FRAGMENT_PATH = os.environ.get("DETECTED_TRANSFORMATION_PATH", "/out/transformation.detected.yml")
OUTPUT_PATH = os.environ.get("GREENMASK_CONFIG_OUTPUT", "/var/lib/greenmask/config.generated.yml")


def _dbname_string(host_env, port_env, user_env, password_env, default_db_env, fallback_db):
    """Build a pg_dump/pg_restore `dbname=` connection string from env vars if
    the job runner set them (arbitrary DSN/uploaded-dump sources), falling
    back to whatever the template already has (the docker_local Adventure
    Works source keeps working unchanged)."""
    host = os.environ.get(host_env)
    if not host:
        return None
    port = os.environ.get(port_env, "5432")
    user = os.environ.get(user_env, "postgres")
    password = os.environ.get(password_env, "")
    dbname = os.environ.get(default_db_env, fallback_db)
    return f"host={host} port={port} user={user} password={password} dbname={dbname}"


def main():
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # dump reads from the SOURCE (DBHOST/etc — the original database, which
    # for a dsn/upload source can be an external, third-party server).
    dump_dbname = _dbname_string("DBHOST", "DBPORT", "DBUSER", "DBPASSWORD", "ORIGINAL_DB_NAME", "original")
    if dump_dbname:
        config.setdefault("dump", {}).setdefault("pg_dump_options", {})["dbname"] = dump_dbname
    # restore writes to the TARGET (TARGET_DBHOST/etc — always OUR OWN
    # playground-db, never the source's server). Deliberately a *different*
    # set of env vars from dump above, not the same DBHOST with a different
    # dbname — conflating them was a real incident where the sanitized copy
    # got created on a client's remote server instead of ours. When
    # TARGET_DBHOST isn't set at all (manual docker_local usage per
    # README.md, which passes no -e flags to `greenmask restore`), this
    # returns None and config.template.yml's own static
    # restore.pg_restore_options.dbname (playground-db/transformed) is left
    # untouched — that template default *is* the fallback, not another env
    # var chain here.
    restore_dbname = _dbname_string(
        "TARGET_DBHOST", "TARGET_DBPORT", "TARGET_DBUSER", "TARGET_DBPASSWORD",
        "TRANSFORMED_DB_NAME", "transformed",
    )
    if restore_dbname:
        config.setdefault("restore", {}).setdefault("pg_restore_options", {})["dbname"] = restore_dbname

    if os.path.exists(FRAGMENT_PATH):
        with open(FRAGMENT_PATH, "r", encoding="utf-8") as f:
            fragment = yaml.safe_load(f) or {}
        config.setdefault("dump", {})["transformation"] = fragment.get("transformation", [])
    else:
        print(f"merge_config: {FRAGMENT_PATH} not found, run detector first", file=sys.stderr)
        sys.exit(1)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"merge_config: wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
