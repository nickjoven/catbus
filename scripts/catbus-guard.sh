#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: catbus-guard.sh [--cid <cid>] [--] [command ...]" >&2
  echo "or: CATBUS_CID=<cid> catbus-guard.sh [--] [command ...]" >&2
}

cid=""
if [[ "${1:-}" == "--cid" ]]; then
  cid="${2:-}"
  shift 2
elif [[ "${1:-}" != "--" && "${1:-}" != "" ]]; then
  cid="$1"
  shift
fi

if [[ -z "$cid" ]]; then
  cid="${CATBUS_CID:-}"
fi

if [[ -z "$cid" ]]; then
  usage
  exit 2
fi

if [[ "${1:-}" == "--" ]]; then
  shift
fi

catbus validate "$cid" >/dev/null
catbus handoff "$cid"

if [[ "$#" -gt 0 ]]; then
  exec "$@"
fi
