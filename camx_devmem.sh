#!/usr/bin/env bash
# camx_devmem.sh — execute memory read/write ops from a JSON file using devmem
# Requires: jq, devmem2
#
# JSON format (array of objects):
# [
#   {"type": "write", "address": "0xffffff80091e0008", "value": "0x00001000"},
#   {"type": "read",  "address": "0xffffff80091e0004", "value": "0x00000000"}  # value optional (used for verify)
# ]
#
# Usage:
#   sudo ./run_mem_ops.sh -f memory_accesses.json [-w 32|64] [--dry-run] [--verify]
#
# Notes:
# - Default WIDTH is 32 (bits). devmem supports 8,16,32,64 but your log data looks 32-bit.
# - Reads print the value returned by devmem.
# - With --verify, reads compare against JSON "value" (if present) and report mismatch.

set -euo pipefail

JSON_FILE=""
WIDTH=32
DRY_RUN=0
VERIFY=0

die() { echo "Error: $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

print_help() {
  cat <<EOF
Usage: sudo $0 -f <ops.json> [-w 8|16|32|64] [--dry-run] [--verify]

Options:
  -f <file>       Input JSON file with operations (array of objects).
  -w <width>      Access width in bits for devmem (default: 32). Allowed: 8,16,32,64.
  --dry-run       Show what would be executed without touching memory.
  --verify        On read ops, if JSON includes 'value', verify devmem result.

Examples:
  sudo $0 -f memory_accesses.json
  sudo $0 -f memory_accesses.json -w 64 --verify
  sudo $0 -f memory_accesses.json --dry-run
EOF
}

# --- parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f) JSON_FILE="${2:-}"; shift 2 ;;
    -w) WIDTH="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --verify) VERIFY=1; shift ;;
    -h|--help) print_help; exit 0 ;;
    *) die "Unknown argument: $1 (use -h for help)";;
  }
done

[[ -n "$JSON_FILE" ]] || { print_help; die "No JSON file specified."; }
[[ -r "$JSON_FILE" ]] || die "Cannot read JSON file: $JSON_FILE"
[[ "$WIDTH" =~ ^(8|16|32|64)$ ]] || die "Width must be one of: 8,16,32,64"

need_cmd jq
need_cmd devmem

# Root is generally required for devmem (unless capabilities are set).
if [[ $DRY_RUN -eq 0 ]] && [[ "$EUID" -ne 0 ]]; then
  die "This script should be run as root for devmem access (or use --dry-run)."
fi

# Normalize hex like: "0x1" -> "0x00000001" (width-based zero-padding) for comparisons.
normalize_hex() {
  local val="$1" bits="$2"
  # Ensure 0x prefix
  if [[ ! "$val" =~ ^0[xX] ]]; then
    val="0x${val}"
  fi
  # Lowercase
  val="${val,,}"
  # Strip 0x for padding calculations
  local hex="${val#0x}"
  # Expected nibble count based on width
  local nibbles=$(( bits / 4 ))
  printf "0x%0${nibbles}s" "$hex" | tr ' ' '0'
}

# Iterate over JSON and perform ops
# Fields: type, address, value (value optional for read)
total=0
writes=0
reads=0
fails=0

# jq outputs TSV: type \t address \t value_or_empty
# Note: value may be null; convert to empty string with // ""
while IFS=$'\t' read -r op addr val; do
  (( total++ ))
  op="${op,,}"                         # lower
  addr="${addr,,}"
  val="${val,,}"

  # devmem accepts hex with 0x prefix; ensure present for value
  [[ -n "$val" ]] && val="$(normalize_hex "$val" "$WIDTH")"

  if [[ "$op" == "write" ]]; then
    (( writes++ ))
    if [[ -z "$val" ]]; then
      echo "[$total] SKIP write @ $addr (no value provided in JSON)" >&2
      continue
    fi
    echo "[$total] WRITE width=${WIDTH} @ ${addr} = ${val}"
    if [[ $DRY_RUN -eq 0 ]]; then
      devmem "$addr" "$WIDTH" "$val"
    fi

  elif [[ "$op" == "read" ]]; then
    (( reads++ ))
    echo -n "[$total] READ  width=${WIDTH} @ ${addr}"
    if [[ $DRY_RUN -eq 0 ]]; then
      out="$(devmem "$addr" "$WIDTH")"   # e.g., 0x00000001
    else
      out="0xDEADBEEF"
    fi
    echo " -> $out"

    # Optional verify
    if [[ $VERIFY -eq 1 && -n "$val" ]]; then
      exp="$(normalize_hex "$val" "$WIDTH")"
      got="$(normalize_hex "$out" "$WIDTH")"
      if [[ "$got" != "$exp" ]]; then
        echo "       MISMATCH: expected $exp, got $got" >&2
        (( fails++ ))
      else
        echo "       OK: matches expected $exp"
      fi
    fi

  else
    echo "[$total] SKIP unknown op '$op' (line $total)" >&2
  fi
done < <(jq -r '.[] | "\(.type)\t\(.address)\t\(.value // "")"' "$JSON_FILE")

echo ""
echo "Summary: total=$total writes=$writes reads=$reads mismatches=$fails"
[[ $fails -gt 0 ]] && exit 2 || exit 0
