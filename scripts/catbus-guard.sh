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

# A packet with no artifacts can pass a bare `validate`; require them, so the
# gate can actually fail (sieve audit, 2026-09-05).
catbus validate "$cid" --require-artifacts >/dev/null
handoff="$(catbus handoff "$cid")"
printf '%s\n' "$handoff"

if [[ "$#" -gt 0 ]]; then
  # Hand the context to the agent, not just to this terminal.
  export CATBUS_CID="$cid" CATBUS_HANDOFF="$handoff"
  exec "$@"
fi
