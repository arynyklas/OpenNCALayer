#!/usr/bin/env bash
# The snapshots of tuf/v2 between the jobs of pages.yml (docs/dev/release.md, section 7g):
# the `snapshot` job signs `<N>.snapshot.json` (and keeps the published one beside it), and
# hands them on as one job output, a base64 gzip tar of at most 100 KiB.
#
#   tuf-v2-snapshots.sh pack <metadata dir> <output file>
#       Writes the encoded snapshots of <metadata dir> to <output file>.
#   tuf-v2-snapshots.sh unpack <metadata dir>
#       Decodes $SNAPSHOTS and extracts the snapshots into <metadata dir>.
#
# Only the names `<N>.snapshot.json`, one or two of them, are packed or extracted; anything
# else, or an encoding over the cap, is an error.
set -euo pipefail

CAP=102400

fail() {
  echo "::error::$1"
  exit 1
}

check_names() {
  [ "$#" -ge 1 ] && [ "$#" -le 2 ] || fail "tuf/v2: $# snapshot files, not one or two"
  for name in "$@"; do
    [[ "$name" =~ ^[0-9]{1,20}\.snapshot\.json$ ]] || fail "tuf/v2: '$name' is not <N>.snapshot.json"
  done
}

case "${1:-}" in
  pack)
    out="$3"
    case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
    cd "$2"
    shopt -s nullglob
    names=(*.snapshot.json)
    check_names "${names[@]}"
    encoded=$(tar -czf - -- "${names[@]}" | base64 -w0)
    if [ "${#encoded}" -gt "$CAP" ]; then
      fail "tuf/v2: the encoded snapshots are ${#encoded} bytes, over the cap of $CAP (docs/dev/release.md, section 7g)"
    fi
    printf '%s' "$encoded" > "$out"
    ;;
  unpack)
    [ -n "${SNAPSHOTS:-}" ] || fail "tuf/v2: no snapshots to unpack"
    if [ "${#SNAPSHOTS}" -gt "$CAP" ]; then
      fail "tuf/v2: the encoded snapshots are ${#SNAPSHOTS} bytes, over the cap of $CAP"
    fi
    archive=$(mktemp)
    printf '%s' "$SNAPSHOTS" | base64 -d > "$archive"
    mapfile -t names < <(tar -tzf "$archive")
    check_names "${names[@]}"
    tar -xzf "$archive" --no-same-owner -C "$2" -- "${names[@]}"
    rm -f "$archive"
    ;;
  *)
    fail "usage: tuf-v2-snapshots.sh pack <metadata dir> <output file> | unpack <metadata dir>"
    ;;
esac
