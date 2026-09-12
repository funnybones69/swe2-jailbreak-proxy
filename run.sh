#!/usr/bin/env bash
# swe2-jailbreak-proxy - POSIX launcher
set -euo pipefail
cd "$(dirname "$0")"

export JB_SWE_HOST="${JB_SWE_HOST:-127.0.0.1}"
export JB_SWE_PORT="${JB_SWE_PORT:-8889}"
# export JB_SWE_SYSTEM_FILE="$PWD/prompts/override-compact.txt"

exec python3 swe2_jb_proxy.py "$@"
