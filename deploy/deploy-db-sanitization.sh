#!/usr/bin/env bash
# Server-side deploy script for db-sanitization's api/worker services.
#
# Lives on guts at /data/projects/deploy-db-sanitization.sh — deploy.py SSHes
# in and runs it. /data/projects/db-sanitization is a real git checkout of
# git@github.com:BabylenMagnus/pg-sanitizer.git (converted from a manual
# tar/scp deploy on 2026-08-11 — see project_wiki/wiki/deployment.md).
#
# Deliberately does NOT touch playground-db/mapping-store/detector/generator/
# greenmask here beyond rebuilding their images if their Dockerfiles/source
# changed — those are pulled in as dependencies by `docker compose up -d
# api worker beat` automatically when their config changes, but this script
# doesn't force-recreate the always-on playground-db/mapping-store data
# services on every deploy (no reason to restart a running Postgres/Redis
# just because api/ changed).
#
# beat: schedules cleanup_target_databases (api/app/tasks.py) — added
# 2026-08-12. New services here must be added to BOTH lines below; Compose
# doesn't infer "also start this" from docker-compose.yml alone.
set -euo pipefail

cd /data/projects/db-sanitization

git fetch origin
git reset --hard origin/master

docker compose build detector generator greenmask api worker beat
docker compose up -d api worker beat
