#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m janitor.cli ./fixtures/notes --offline
