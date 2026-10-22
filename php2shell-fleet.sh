#!/usr/bin/env bash
#
# php2shell-fleet.sh — Run the php2shell audit (and optional forensics) across a fleet via SSH
#
# Copies the audit/forensics scripts to each host, runs them in --json mode,
# and prints a sorted summary so you can triage a whole estate at once.
# Read-only on the targets. Run only against hosts you are authorized to audit.
#
# Usage:
#   ./php2shell-fleet.sh --hosts hosts.txt [--user ops] [--forensics] [--jobs 10]
#
# hosts.txt: one target per line. Lines may be "host", "user@host", or
#            "user@host:port". Blank lines and #comments ignored.
#
# License: MIT
set -uo pipefail

HOSTS_FILE=""; SSH_USER=""; DO_FORENSICS=0; JOBS=8; OUT=""
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() { sed -n '2,16p' "$0"; exit "${1:-0}"; }
for ((i=1;i<=$#;i++)); do a="${!i}"; case "$a" in
  --hosts) ((i++)); HOSTS_FILE="${!i}" ;;
  --hosts=*) HOSTS_FILE="${a#*=}" ;;
  --user) ((i++)); SSH_USER="${!i}" ;;
  --user=*) SSH_USER="${a#*=}" ;;
  --jobs) ((i++)); JOBS="${!i}" ;;
  --jobs=*) JOBS="${a#*=}" ;;
  --out) ((i++)); OUT="${!i}" ;;
  --out=*) OUT="${a#*=}" ;;
  --forensics) DO_FORENSICS=1 ;;
  -h|--help) usage 0 ;;
esac; done

[ -z "$HOSTS_FILE" ] && { echo "error: --hosts <file> required"; usage 1; }
[ ! -r "$HOSTS_FILE" ] && { echo "error: cannot read $HOSTS_FILE"; exit 1; }
[ ! -r "$HERE/php2shell-audit.sh" ] && { echo "error: php2shell-audit.sh not found next to this script"; exit 1; }
command -v ssh >/dev/null || { echo "error: ssh not installed"; exit 1; }

# shared banner (optional — toolkit works without it)
_P2S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -r "$_P2S_DIR/banner.sh" ] && source "$_P2S_DIR/banner.sh" && p2s_banner

TMPDIR_RUN="$(mktemp -d)"; trap 'rm -rf "$TMPDIR_RUN"' EXIT

# reject host strings that could be read as ssh options or shell metachars —
# an entry like "-oProxyCommand=..." must never reach ssh as an option.
valid_target() {
  case "$1" in
    -*) return 1 ;;                                   # leading dash = option injection
    *[\;\|\&\$\`\(\)\<\>\'\"\ ]*) return 1 ;;         # shell metacharacters / spaces
    *) return 0 ;;
  esac
}

run_one() {
  local raw="$1" target port=22 host res verdict rdir
  raw="${raw%%#*}"; raw="$(echo "$raw" | xargs)"; [ -z "$raw" ] && return 0
  target="$raw"
  case "$target" in *:*) port="${target##*:}"; target="${target%:*}" ;; esac
  [ -n "$SSH_USER" ] && case "$target" in *@*) ;; *) target="$SSH_USER@$target" ;; esac
  host="${target#*@}"

  # validate both the full target and the bare host, and the port
  if ! valid_target "$target" || ! valid_target "$host" || ! printf '%s' "$port" | grep -qE '^[0-9]+$'; then
    printf '%s\t%s\t%s\n' "error" "$host" '{"result":"error","reason":"invalid host entry (rejected)"}' >> "$TMPDIR_RUN/results"
    return 0
  fi

  # ship to a RANDOM remote path (mktemp) to avoid a predictable-name TOCTOU/symlink
  # swap on multi-user targets, and always pass "--" before the target.
  rdir="$(ssh -p "$port" "${SSH_OPTS[@]}" -- "$target" 'mktemp -d 2>/dev/null' 2>/dev/null)"
  if [ -z "$rdir" ]; then
    printf '%s\t%s\t%s\n' "unreachable" "$host" '{"result":"unreachable"}' >> "$TMPDIR_RUN/results"; return 0
  fi
  if ! scp -q -P "$port" "${SSH_OPTS[@]}" -- "$HERE/php2shell-audit.sh" "$target:$rdir/audit.sh" 2>/dev/null; then
    ssh -p "$port" "${SSH_OPTS[@]}" -- "$target" "rm -rf -- '$rdir'" 2>/dev/null
    printf '%s\t%s\t%s\n' "unreachable" "$host" '{"result":"unreachable"}' >> "$TMPDIR_RUN/results"; return 0
  fi
  res="$(ssh -p "$port" "${SSH_OPTS[@]}" -- "$target" "bash '$rdir/audit.sh' --json 2>/dev/null" 2>/dev/null)"
  verdict="$(printf '%s' "$res" | grep -oE '"(result|overall)":"[^"]*"' | head -1 | cut -d'"' -f4)"
  [ -z "$verdict" ] && verdict="error"
  printf '%s\t%s\t%s\n' "$verdict" "$host" "$res" >> "$TMPDIR_RUN/results"

  if [ "$DO_FORENSICS" = 1 ] && [ -r "$HERE/php2shell-forensics.sh" ]; then
    if scp -q -P "$port" "${SSH_OPTS[@]}" -- "$HERE/php2shell-forensics.sh" "$target:$rdir/fx.sh" 2>/dev/null; then
      ssh -p "$port" "${SSH_OPTS[@]}" -- "$target" "bash '$rdir/fx.sh' --json 2>/dev/null" 2>/dev/null \
        >> "$TMPDIR_RUN/forensics.$host.json"
    fi
  fi
  # clean up the remote temp dir
  ssh -p "$port" "${SSH_OPTS[@]}" -- "$target" "rm -rf -- '$rdir'" 2>/dev/null
}

# parallel fan-out
pids=0
while IFS= read -r l || [ -n "$l" ]; do
  run_one "$l" &
  pids=$((pids+1))
  if [ "$pids" -ge "$JOBS" ]; then wait -n 2>/dev/null || wait; pids=$((pids-1)); fi
done < "$HOSTS_FILE"
wait

# --- summary ----------------------------------------------------------------
[ -f "$TMPDIR_RUN/results" ] || { echo "No results."; exit 0; }
total=$(wc -l < "$TMPDIR_RUN/results" | xargs)
count() { grep -c "^$1	" "$TMPDIR_RUN/results" 2>/dev/null || echo 0; }

echo ""
echo "============ php2shell fleet summary ($total hosts) ============"
printf '  VULNERABLE      : %s\n' "$(count vulnerable)"
printf '  likely-patched  : %s\n' "$(count likely-patched)"
printf '  patched         : %s\n' "$(count patched)"
printf '  uncertain       : %s\n' "$(count uncertain)"
printf '  unreachable/err : %s\n' "$(( $(count unreachable) + $(count error) ))"
echo ""
echo "--- Hosts needing action (vulnerable first) ---"
for v in vulnerable likely-patched uncertain; do
  grep "^$v	" "$TMPDIR_RUN/results" 2>/dev/null | while IFS=$'\t' read -r verdict host json; do
    ver="$(printf '%s' "$json" | grep -oE '"php_version":"[^"]*"' | cut -d'"' -f4)"
    printf '  [%-14s] %-40s PHP %s\n' "$verdict" "$host" "${ver:-?}"
  done
done

if [ -n "$OUT" ]; then
  { echo "verdict,host,php_version"
    while IFS=$'\t' read -r verdict host json; do
      ver="$(printf '%s' "$json" | grep -oE '"php_version":"[^"]*"' | cut -d'"' -f4)"
      printf '%s,%s,%s\n' "$verdict" "$host" "${ver:-}"
    done < "$TMPDIR_RUN/results"
  } > "$OUT"
  echo ""
  echo "CSV written to $OUT"
  [ "$DO_FORENSICS" = 1 ] && echo "Per-host forensics JSON: $TMPDIR_RUN/forensics.*.json (copy out before exit if you need them)"
fi

# exit non-zero if anything is vulnerable, so CI/cron can alert
[ "$(count vulnerable)" -gt 0 ] && exit 1 || exit 0
