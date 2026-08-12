#!/bin/sh
set -e

python3 /opt/greenmask-tools/merge_config.py
exec greenmask "$@"
