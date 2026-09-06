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
# gate can actually fail (sieve audit, 2026-09-05). validate prints its
# reasons on stdout; keep them visible without mixing them into our output.
catbus validate "$cid" --require-artifacts 1>&2
handoff="$(catbus handoff "$cid")"
printf '%s\n' "$handoff"

if [[ "$#" -gt 0 ]]; then
  # Hand the context to the agent, not just to this terminal. The file is the
  # channel that always works; the env var is a convenience that Linux caps
  # (one env string < 128 KiB, so stay well under it). Not `exec`: the temp
  # file must outlive the child and then be removed.
  handoff_file="$(mktemp -t catbus-handoff.XXXXXXXX)"
  trap 'rm -f "$handoff_file"' EXIT
  printf '%s\n' "$handoff" > "$handoff_file"
  export CATBUS_CID="$cid" CATBUS_HANDOFF_FILE="$handoff_file"
  if (( ${#handoff} < 65536 )); then
    export CATBUS_HANDOFF="$handoff"
  else
    echo "catbus-guard.sh: handoff is ${#handoff} bytes; CATBUS_HANDOFF not set, use CATBUS_HANDOFF_FILE" >&2
  fi
  "$@"
fi
