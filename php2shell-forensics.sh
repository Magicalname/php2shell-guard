#!/usr/bin/env bash
#
# php2shell-forensics.sh — Post-compromise IOC scan for php2shell (CVE-2026-109618/109619)
#
# Searches THIS host for indicators that the php2shell flaws may have been
# exploited. Strictly READ-ONLY: it never deletes, quarantines, or "cleans"
# anything — on a real compromise, automated cleanup destroys the evidence an
# incident responder needs.
#
# IMPORTANT — read this before trusting a clean result:
#   * "No indicators found" means NOT PROVEN COMPROMISED, not "proven safe".
#     A capable attacker clears logs and hides shells.
#   * This tool CANNOT prove whether data was exfiltrated. Exfiltration is
#     almost never provable from a single host after the fact. At best it flags
#     *suspicious outbound signals* for a human to investigate.
#   * Any hit = treat the host as potentially compromised: isolate it, preserve
#     a disk/memory image, and start a real incident-response process.
#
# Run only on hosts you own or are authorized to examine. Best run as root.
#
# License: MIT
set -uo pipefail

VERSION="1.0.0"
C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_CYN=$'\033[36m'; C_B=$'\033[1m'; C_0=$'\033[0m'
JSON=0; DAYS=30; WEBROOTS=(); SESSION_DIRS=()
HITS=0

for a in "$@"; do case "$a" in
  --json) JSON=1 ;;
  --days=*) DAYS="${a#*=}" ;;
  --webroot=*) WEBROOTS+=("${a#*=}") ;;
  -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
esac; done
if [ "$JSON" = 1 ] || [ ! -t 1 ]; then C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_B=""; C_0=""; fi

say() { [ "$JSON" = 1 ] || printf '%s\n' "$*"; }
section() { say ""; say "${C_CYN}${C_B}== $* ==${C_0}"; }

# shared banner (optional — toolkit works without it)
_P2S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -r "$_P2S_DIR/banner.sh" ] && source "$_P2S_DIR/banner.sh" && p2s_banner
FINDINGS_JSON=()
hit()  { HITS=$((HITS+1)); say "  ${C_RED}[!]${C_0} $*"; FINDINGS_JSON+=("$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"); }
ok()   { say "  ${C_GRN}[ok]${C_0} $*"; }
info() { say "  ${C_YLW}[i]${C_0} $*"; }

[ "$(id -u)" -ne 0 ] && info "Not running as root — some paths (session dirs, other users' webroots, /proc) may be unreadable; results are partial."

# --- discover webroots & session dirs if not given --------------------------
if [ "${#WEBROOTS[@]}" -eq 0 ]; then
  for d in /var/www /srv/www /usr/share/nginx/html /var/www/html /home/*/public_html /home/*/www; do
    [ -d "$d" ] && WEBROOTS+=("$d")
  done
fi
for d in /var/lib/php/sessions /var/lib/php/session /tmp /var/tmp; do
  [ -d "$d" ] && SESSION_DIRS+=("$d")
done

# ---------------------------------------------------------------------------
section "1. Web/PHP logs — attack signatures"
LOGS=()
for g in /var/log/nginx/*access*log /var/log/apache2/*access*log /var/log/httpd/*access*log \
         /var/log/php*-fpm.log /var/log/php*fpm*.log /var/log/php_errors.log; do
  [ -r "$g" ] && LOGS+=("$g")
done
if [ "${#LOGS[@]}" -eq 0 ]; then
  info "No readable web/php logs found in standard locations."
else
  # Primary IOC: the upload_progress key in request traffic.
  # NUL-delimited + while-read: safe against log filenames crafted by an attacker
  # on a host we are, by definition, treating as possibly compromised.
  found_up=0
  while IFS= read -r -d '' L; do
    found_up=1
    c="$(grep -ciE 'PHP_SESSION_UPLOAD_PROGRESS' "$L" 2>/dev/null || true)"; c="${c:-0}"
    hit "PHP_SESSION_UPLOAD_PROGRESS seen $c time(s) in $L — core attack-vector string."
  done < <(grep -lsiEZ 'PHP_SESSION_UPLOAD_PROGRESS' "${LOGS[@]}" 2>/dev/null)
  [ "$found_up" -eq 0 ] && ok "No PHP_SESSION_UPLOAD_PROGRESS strings in readable logs."
  # Secondary: 502 clusters (FPM worker crashes from OOM) + webshell-ish requests
  for L in "${LOGS[@]}"; do
    f502="$(grep -cE '" 502 ' "$L" 2>/dev/null || true)"; f502="${f502:-0}"
    [ "$f502" -ge 50 ] 2>/dev/null && info "$f502 x HTTP 502 in $L — worker crashes can indicate OOM-trigger attempts (also many benign causes)."
  done
  if grep -lsiE '\.php\?[^ ]*(cmd|exec|shell|system)=' "${LOGS[@]}" >/dev/null 2>&1; then
    hit "Requests with cmd/exec/shell/system query params found — possible webshell interaction. Review manually."
  else
    ok "No obvious webshell-style request params in logs."
  fi
fi

# ---------------------------------------------------------------------------
section "2. Webroots — suspicious / recently written PHP files"
if [ "${#WEBROOTS[@]}" -eq 0 ]; then
  info "No webroots found/given. Pass --webroot=/path to target yours."
else
  for W in "${WEBROOTS[@]}"; do
    # recently modified php files
    recent="$(find "$W" -type f -name '*.php' -mtime -"$DAYS" 2>/dev/null | head -200)"
    if [ -n "$recent" ]; then
      cnt="$(printf '%s\n' "$recent" | grep -c . )"
      info "$cnt PHP file(s) modified in last ${DAYS}d under $W (expected after deploys — review the unexpected ones):"
      printf '%s\n' "$recent" | head -20 | while read -r f; do say "        $f"; done
    fi
    # webshell heuristics: dangerous sinks + obfuscation in one file
    shells="$(grep -rlsE '(eval|assert|system|passthru|shell_exec|proc_open|popen)[[:space:]]*\(' "$W" --include='*.php' 2>/dev/null \
               | xargs -r grep -lsE '(base64_decode|gzinflate|str_rot13|\\\\x[0-9a-f]{2}|\$_(GET|POST|REQUEST|COOKIE)\[)' 2>/dev/null | head -50)"
    if [ -n "$shells" ]; then
      printf '%s\n' "$shells" | while read -r f; do hit "Possible webshell (dangerous sink + obfuscation/user-input): $f"; done
    else
      ok "No files combining dangerous sinks with obfuscation under $W."
    fi
  done
fi

# ---------------------------------------------------------------------------
section "3. Session files containing PHP code"
found_sess=0
for S in "${SESSION_DIRS[@]}"; do
  bad="$(grep -rlsE '<\?php|__destruct|O:[0-9]+:' "$S"/sess_* 2>/dev/null | head -50)"
  if [ -n "$bad" ]; then
    found_sess=1
    printf '%s\n' "$bad" | while read -r f; do hit "Session file holds PHP/serialized-object markers: $f"; done
  fi
done
[ "$found_sess" -eq 0 ] && ok "No session files with embedded PHP/object markers (in readable dirs)."

# ---------------------------------------------------------------------------
section "4. Persistence — cron, SSH keys, SUID, recent system binaries"
# cron
newcron="$(find /etc/cron* /var/spool/cron -type f -mtime -"$DAYS" 2>/dev/null | head -50)"
[ -n "$newcron" ] && printf '%s\n' "$newcron" | while read -r f; do info "Recently changed cron entry: $f (verify it's yours)"; done || ok "No cron files changed in last ${DAYS}d."
# authorized_keys recently touched
akeys="$(find /root/.ssh /home/*/.ssh -name authorized_keys -mtime -"$DAYS" 2>/dev/null | head -50)"
[ -n "$akeys" ] && printf '%s\n' "$akeys" | while read -r f; do hit "authorized_keys modified in last ${DAYS}d: $f — confirm every key belongs to you."; done || ok "No authorized_keys changed in last ${DAYS}d."
# world-writable or recent SUID in odd places
oddsuid="$(find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null | head -50)"
[ -n "$oddsuid" ] && printf '%s\n' "$oddsuid" | while read -r f; do hit "SUID binary in a temp dir (highly abnormal): $f"; done || ok "No SUID binaries in temp dirs."

# ---------------------------------------------------------------------------
section "5. Outbound / exfiltration SIGNALS (indicative only — not proof)"
info "A single host cannot prove whether data left it. These are leads for a human, not a verdict."
if command -v ss >/dev/null 2>&1; then
  estab="$(ss -tnp state established 2>/dev/null | grep -vE '127\.0\.0\.1|::1|:22 |:80 |:443 |:3306 ' | tail -n +2 | head -30)"
  if [ -n "$estab" ]; then
    info "Established outbound connections to review (excluding localhost & common service ports):"
    printf '%s\n' "$estab" | while read -r line; do say "        $line"; done
  else
    ok "No unusual established outbound connections right now (point-in-time snapshot only)."
  fi
fi
# reverse-shell-ish processes
if command -v ps >/dev/null 2>&1; then
  rsh="$(ps -eo args 2>/dev/null | grep -E '(bash|sh|nc|ncat|python|perl)[^|]*(-i|/dev/tcp/|-e[[:space:]])' | grep -v grep | head -20)"
  [ -n "$rsh" ] && printf '%s\n' "$rsh" | while read -r p; do hit "Process resembles an interactive/reverse shell: $p"; done || ok "No obvious reverse-shell process patterns."
fi

# ---------------------------------------------------------------------------
section "Verdict"
if [ "$JSON" = 1 ]; then
  printf '{"host":"%s","tool_version":"%s","ioc_hits":%d,"status":"%s","findings":[' \
    "$(hostname)" "$VERSION" "$HITS" "$([ "$HITS" -eq 0 ] && echo no-iocs-found || echo iocs-found)"
  for i in "${!FINDINGS_JSON[@]}"; do [ "$i" -gt 0 ] && printf ','; printf '"%s"' "${FINDINGS_JSON[$i]}"; done
  printf ']}\n'
elif [ "$HITS" -eq 0 ]; then
  say "${C_GRN}${C_B}No indicators of compromise found.${C_0}"
  say "This is ${C_B}not${C_0} proof the host is clean — a skilled attacker hides tracks and wipes logs."
  say "If you had an exposed, unpatched window, still patch, rotate secrets, and keep monitoring."
else
  say "${C_RED}${C_B}$HITS indicator(s) of compromise found.${C_0} Treat this host as potentially breached:"
  say "  1. ${C_B}Isolate${C_0} it from the network (don't power off — you lose memory evidence)."
  say "  2. ${C_B}Preserve evidence${C_0}: snapshot disk + RAM before changing anything."
  say "  3. ${C_B}Rotate all secrets${C_0} the host could reach (DB creds, API keys, SSH keys, session secrets)."
  say "  4. ${C_B}Start real IR${C_0} — do not rely on this script to 'clean' anything. Rebuild from known-good, don't just delete shells."
  say "  5. Assume data accessible to this host ${C_B}may${C_0} have been exposed; handle per your breach-notification duties."
fi

[ "$HITS" -eq 0 ] && exit 0 || exit 1
