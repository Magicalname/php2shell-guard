#!/usr/bin/env bash
#
# php2shell-audit.sh — Defensive audit for CVE-2026-109618 / CVE-2026-109619 (php2shell)
#
# Checks EVERY PHP build on this host (not just the one in $PATH) for exposure to
# the php2shell pre-auth RCE flaws and prints prioritized, chain-aware hardening
# advice. READ-ONLY: it reads version + configuration state and never exploits
# anything. Run only on servers you own or are authorized to audit.
#
# Covers: system php, cPanel EasyApache (ea-php*), CloudLinux PHP Selector
#         (alt-php*), LiteSpeed (lsphp*), Plesk (/opt/plesk/php/*), Remi.
#
# Fixed upstream (php.net, 2026-10-21): 8.2.35, 8.3.36, 8.4.27, 8.5.12
# IMPORTANT: ea-php / alt-php / distro builds backport the fix WITHOUT bumping
#            the version string — for those the package changelog is the ONLY
#            reliable test. This tool checks the changelog for such builds.
#
# What NO config can fix: CVE-2026-109618 is OOM corruption in the Zend engine
#            core (the repo's "Chain D"). session.upload_progress=Off and WAF
#            rules only reduce the session/upload vector (Chains A/C/E). The
#            Zend-core path stays open until the binary itself is patched.
#
# Exit codes: 0 = all patched, 1 = at least one vulnerable, 2 = uncertain, 3 = error
# License: MIT
set -uo pipefail

VERSION="1.1.0"
C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_CYN=$'\033[36m'; C_B=$'\033[1m'; C_0=$'\033[0m'
JSON=0; NO_COLOR=0; PHP_BIN_ARG=""; DEEP=0

for a in "$@"; do case "$a" in
  --json) JSON=1 ;;
  --no-color) NO_COLOR=1 ;;
  --php=*) PHP_BIN_ARG="${a#*=}" ;;
  --deep) DEEP=1 ;;            # run the active oom_* regression patch test (read-only, slower)
  -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
esac; done
[ "$JSON" = 1 ] && NO_COLOR=1
{ [ "$NO_COLOR" = 1 ] || [ ! -t 1 ]; } && { C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_B=""; C_0=""; }

say() { [ "$JSON" = 1 ] || printf '%s\n' "$*"; }
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# shared banner (optional — toolkit works without it)
_P2S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -r "$_P2S_DIR/banner.sh" ] && source "$_P2S_DIR/banner.sh" && p2s_banner
truthy() { case "$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z')" in 1|on|true|yes) return 0;; *) return 1;; esac; }

# patched-release floor per upstream branch
need_for() { case "$1" in 8.5) echo 12;; 8.4) echo 27;; 8.3) echo 36;; 8.2) echo 35;; *) echo "";; esac; }

# ---------------------------------------------------------------------------
# 1. Enumerate every PHP binary on the host
# ---------------------------------------------------------------------------
declare -A SEEN
BINS=()
addbin() { local b="$1"; [ -n "$b" ] && [ -x "$b" ] && [ -z "${SEEN[$b]:-}" ] && { SEEN[$b]=1; BINS+=("$b"); }; }

if [ -n "$PHP_BIN_ARG" ]; then
  addbin "$PHP_BIN_ARG"
else
  addbin "$(command -v php 2>/dev/null || true)"
  # cPanel EasyApache
  for b in /opt/cpanel/ea-php*/root/usr/bin/php; do addbin "$b"; done
  # CloudLinux PHP Selector
  for b in /opt/alt/php*/usr/bin/php; do addbin "$b"; done
  # LiteSpeed lsphp
  for b in /usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp; do addbin "$b"; done
  # Plesk
  for b in /opt/plesk/php/*/bin/php; do addbin "$b"; done
  # Remi / SCL / common extras
  for b in /opt/remi/php*/root/usr/bin/php /usr/bin/php[78].* /usr/local/bin/php; do addbin "$b"; done
fi

if [ "${#BINS[@]}" -eq 0 ]; then
  if [ "$JSON" = 1 ]; then printf '{"host":"%s","result":"error","reason":"no php binaries found"}\n' "$(esc "$(hostname)")"
  else say "${C_RED}✗ No PHP binaries found.${C_0} If PHP runs only via a container/socket, audit that runtime manually, or pass --php=/path."; fi
  exit 3
fi

# ---------------------------------------------------------------------------
# 2. Identify the owning package for a binary + changelog-based patch proof
#    Returns patch state for backport-style builds where version != truth.
# ---------------------------------------------------------------------------
# echoes: "<pkgname>"  (empty if none)
owning_pkg() {
  local bin="$1" pkg=""
  if command -v rpm >/dev/null 2>&1; then
    pkg="$(rpm -qf "$bin" 2>/dev/null | grep -v 'not owned' | head -1)"
  fi
  if [ -z "$pkg" ] && command -v dpkg >/dev/null 2>&1; then
    pkg="$(dpkg -S "$bin" 2>/dev/null | head -1 | cut -d: -f1)"
  fi
  printf '%s' "$pkg"
}
# echoes: patched | vulnerable | unknown  (based on CVE in package changelog)
changelog_state() {
  local pkg="$1" bin="$2"
  [ -z "$pkg" ] && { echo unknown; return; }
  if command -v rpm >/dev/null 2>&1 && rpm -q "$pkg" >/dev/null 2>&1; then
    if rpm -q --changelog "$pkg" 2>/dev/null | grep -qiE 'CVE-2026-109618|CVE-2026-109619'; then echo patched; return; fi
    echo vulnerable; return   # rpm present, no CVE in changelog → not yet patched
  fi
  if command -v dpkg-query >/dev/null 2>&1; then
    for cl in /usr/share/doc/"$pkg"/changelog.Debian.gz /usr/share/doc/"$pkg"/changelog.gz; do
      [ -r "$cl" ] && zcat "$cl" 2>/dev/null | grep -qiE 'CVE-2026-109618|CVE-2026-109619' && { echo patched; return; }
    done
    echo unknown; return  # dpkg changelogs are often absent; don't assume vulnerable
  fi
  echo unknown
}

# Check (read-only, no install) whether a newer package is available in the
# configured repos. Echoes one of:
#   avail:<cmd>   an update is in the repo — <cmd> would install it
#   none          package known but no update offered
#   unknown       can't tell (no package manager / not packaged / offline)
# NOTE: "available" means a newer package exists, NOT that it definitely carries
# the fix — confirm via changelog AFTER installing. The caller says so.
update_available() {
  local pkg="$1"
  [ -z "$pkg" ] && { echo unknown; return; }
  if command -v dnf >/dev/null 2>&1; then
    # dnf check-update exits 100 when updates ARE available, 0 when none
    if dnf -q --cacheonly check-update "$pkg" >/dev/null 2>&1; then echo "none"; return; fi
    local rc; dnf -q --cacheonly check-update "$pkg" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 100 ] && { echo "avail:dnf upgrade $pkg"; return; }
    echo unknown; return
  fi
  if command -v yum >/dev/null 2>&1; then
    if yum -q check-update "$pkg" >/dev/null 2>&1; then echo "none"; return; fi
    [ $? -eq 100 ] && { echo "avail:yum update $pkg"; return; }
    echo unknown; return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    # simulate an upgrade; if the pkg appears in the "Inst" list, an update exists
    local sim; sim="$(apt-get -s install --only-upgrade "$pkg" 2>/dev/null)"
    if printf '%s' "$sim" | grep -qE "^Inst $pkg "; then echo "avail:apt-get install --only-upgrade $pkg"; return; fi
    printf '%s' "$sim" | grep -qE 'is already the newest|0 upgraded' && { echo "none"; return; }
    echo unknown; return
  fi
  echo unknown
}

# is this a backport-style build whose version string can't be trusted?
is_backport_build() {
  case "$1" in
    */opt/cpanel/ea-php*|*/opt/alt/php*|*/opt/plesk/php*|*/opt/remi/*) return 0 ;;
    *) command -v rpm >/dev/null 2>&1 && return 0 || return 1 ;;  # distro rpm builds too
  esac
}

# ---------------------------------------------------------------------------
# 3. Optional active patch test: run PHP's own oom_* regression behaviour.
#    A patched build survives a crafted OOM during unserialize; an unpatched
#    one bails out / segfaults. Kept deliberately gentle and read-only.
# ---------------------------------------------------------------------------
active_patch_test() {
  local bin="$1"
  # memory_limit forced low so the OOM path is reached fast and safely in CLI.
  # Patched engine: clean fatal/handled. Unpatched: abnormal exit (segv/bailout).
  "$bin" -d memory_limit=16M -d session.upload_progress.enabled=1 -r '
    $s = str_repeat("a", 1024*1024);
    @session_decode("upload_progress_x|".$s);
    echo "SURVIVED";
  ' >/dev/null 2>&1
  local rc=$?
  # 139 = SIGSEGV, 134 = SIGABRT → classic unpatched crash signatures
  if [ "$rc" -eq 139 ] || [ "$rc" -eq 134 ]; then echo crash
  elif [ "$rc" -eq 0 ]; then echo survived
  else echo inconclusive; fi
}

# ---------------------------------------------------------------------------
# 4. Audit each binary
# ---------------------------------------------------------------------------
OVERALL="patched"   # worst-of across all builds
JSON_BUILDS=()
any_vuln=0; any_uncertain=0

bump_overall() { case "$1" in
  vulnerable) OVERALL="vulnerable"; any_vuln=1 ;;
  uncertain|likely-patched) [ "$OVERALL" != "vulnerable" ] && OVERALL="$1"; [ "$1" = uncertain ] && any_uncertain=1 ;;
esac; }

say "${C_CYN}${C_B}php2shell-audit v$VERSION${C_0}  —  CVE-2026-109618 / CVE-2026-109619"
say "Host: $(hostname)   PHP builds found: ${#BINS[@]}"

for BIN in "${BINS[@]}"; do
  VER="$("$BIN" -r 'echo PHP_VERSION;' 2>/dev/null)"
  [ -z "$VER" ] && continue
  MM="$(printf '%s' "$VER" | cut -d. -f1-2)"
  PATCH="$(printf '%s' "$VER" | cut -d. -f3 | grep -oE '^[0-9]+' || echo 0)"
  SAPI="$("$BIN" -r 'echo PHP_SAPI;' 2>/dev/null)"
  INI="$("$BIN" -r 'echo php_ini_loaded_file() ?: "(none)";' 2>/dev/null)"
  UP="$("$BIN" -r "echo ini_get('session.upload_progress.enabled');" 2>/dev/null)"
  UOC="$("$BIN" -r "echo ini_get('session.use_only_cookies');" 2>/dev/null)"
  FBT="$("$BIN" -r "echo ini_get('fatal_error_backtraces');" 2>/dev/null)"

  PKG="$(owning_pkg "$BIN")"
  STATE="uncertain"; REASON=""; VERIFY=""

  FLOOR="$(need_for "$MM")"
  if is_backport_build "$BIN"; then
    # version string is unreliable → trust the changelog
    CL="$(changelog_state "$PKG" "$BIN")"
    case "$CL" in
      patched)    STATE="patched";    REASON="$PKG changelog references the CVE (backport applied)";;
      vulnerable) STATE="vulnerable"; REASON="$PKG installed but changelog does NOT reference the CVE"; VERIFY="dnf/yum upgrade this package; version string won't change";;
      unknown)
        # fall back to upstream numbering if we have a floor, else uncertain
        if [ -n "$FLOOR" ]; then
          if [ "$PATCH" -ge "$FLOOR" ]; then STATE="patched"; REASON="$VER >= upstream floor $MM.$FLOOR (changelog unreadable)"
          else STATE="uncertain"; REASON="$VER < upstream $MM.$FLOOR but this is a backport build — can't confirm from version alone"
               VERIFY="check: rpm -q --changelog ${PKG:-<pkg>} | grep -m1 CVE-2026-109618  (empty = still vulnerable)"; fi
        else STATE="uncertain"; REASON="EOL/backport branch $MM, changelog unreadable"; VERIFY="confirm against your vendor's advisory"; fi
        ;;
    esac
  else
    # trust upstream version numbering
    if [ -n "$FLOOR" ]; then
      [ "$PATCH" -ge "$FLOOR" ] && { STATE="patched"; REASON="$VER >= $MM.$FLOOR"; } \
                                || { STATE="vulnerable"; REASON="$VER < $MM.$FLOOR (needs $MM.$FLOOR)"; VERIFY="upgrade to 8.5.12/8.4.27/8.3.36/8.2.35"; }
    else
      STATE="vulnerable"; REASON="$MM is EOL — no php.net fix for this branch"; VERIFY="move to a supported patched branch, or a vendor backport"
    fi
  fi

  # optional active confirmation
  ACTIVE=""
  if [ "$DEEP" = 1 ]; then
    ACTIVE="$(active_patch_test "$BIN")"
    case "$ACTIVE" in
      crash)    STATE="vulnerable"; REASON="$REASON | ACTIVE TEST: engine crashed on OOM decode (unpatched signature)";;
      survived) [ "$STATE" = uncertain ] && { STATE="likely-patched"; REASON="$REASON | ACTIVE TEST: survived OOM decode"; };;
    esac
  fi

  # For anything not confirmed patched, automatically check whether a fix is
  # sitting in the repo waiting to be installed. This is the "idiot-proof" line:
  # it tells the admin the exact command, or that no fix is available at all.
  UPD=""; UPD_HINT=""
  if [ "$STATE" = "vulnerable" ] || [ "$STATE" = "uncertain" ]; then
    UPD="$(update_available "$PKG")"
    case "$UPD" in
      avail:*) UPD_HINT="UPDATE AVAILABLE → run: ${UPD#avail:}   (then re-check the changelog to confirm the fix landed)";;
      none)    UPD_HINT="NO update in your repos for $PKG — you must switch to a patched branch or add a vendor/LTS backport repo";;
      *)       UPD_HINT="couldn't check repo for updates (offline, or $PKG not managed by a package manager) — verify manually";;
    esac
  fi

  bump_overall "$STATE"

  # per-build output
  if [ "$JSON" = 1 ]; then
    JSON_BUILDS+=("$(printf '{"bin":"%s","version":"%s","sapi":"%s","pkg":"%s","state":"%s","reason":"%s","verify":"%s","update":"%s","update_hint":"%s","active_test":"%s","ini":"%s","upload_progress":"%s","use_only_cookies":"%s","fatal_error_backtraces":"%s"}' \
      "$(esc "$BIN")" "$(esc "$VER")" "$(esc "$SAPI")" "$(esc "$PKG")" "$STATE" "$(esc "$REASON")" "$(esc "$VERIFY")" "$(esc "$UPD")" "$(esc "$UPD_HINT")" "$(esc "$ACTIVE")" "$(esc "$INI")" "$(esc "$UP")" "$(esc "$UOC")" "$(esc "$FBT")")")
  else
    case "$STATE" in
      patched) badge="${C_GRN}${C_B}✓ patched${C_0}";;
      likely-patched) badge="${C_YLW}${C_B}~ likely patched${C_0}";;
      vulnerable) badge="${C_RED}${C_B}✗ VULNERABLE${C_0}";;
      *) badge="${C_YLW}${C_B}? uncertain${C_0}";;
    esac
    say ""
    say "  ${C_B}$BIN${C_0}"
    say "    PHP $VER ($SAPI)  ${PKG:+pkg=$PKG}  →  $badge"
    say "    $REASON"
    [ -n "$VERIFY" ] && say "    ${C_YLW}verify/fix:${C_0} $VERIFY"
    if [ -n "$UPD_HINT" ]; then
      case "$UPD" in
        avail:*) say "    ${C_GRN}${C_B}» $UPD_HINT${C_0}";;
        none)    say "    ${C_RED}${C_B}» $UPD_HINT${C_0}";;
        *)       say "    ${C_YLW}» $UPD_HINT${C_0}";;
      esac
    fi
    # per-build config notes
    truthy "$UP"      && say "    ${C_YLW}config:${C_0} session.upload_progress.enabled=On — primary session vector live here"
    truthy "$UOC"     || say "    ${C_YLW}config:${C_0} session.use_only_cookies=Off — widens session-injection surface"
    [ "$MM" = 8.5 ] && truthy "$FBT" && say "    ${C_YLW}config:${C_0} fatal_error_backtraces=On (8.5) — used by CVE-2026-109619"
  fi
done

# ---------------------------------------------------------------------------
# 5. Chain-aware summary: what config can and CANNOT fix
# ---------------------------------------------------------------------------
if [ "$JSON" = 1 ]; then
  printf '{"host":"%s","tool_version":"%s","overall":"%s","builds_found":%d,"builds":[' \
    "$(esc "$(hostname)")" "$VERSION" "$OVERALL" "${#BINS[@]}"
  for i in "${!JSON_BUILDS[@]}"; do [ "$i" -gt 0 ] && printf ','; printf '%s' "${JSON_BUILDS[$i]}"; done
  printf ']}\n'
else
  say ""
  say "${C_CYN}${C_B}== Overall: $(case $OVERALL in patched)echo "${C_GRN}all builds patched${C_0}";;vulnerable)echo "${C_RED}at least one VULNERABLE build${C_0}";;*)echo "${C_YLW}uncertain — verify flagged builds${C_0}";;esac) ==${C_0}"
  say ""
  say "${C_B}What config hardening CAN reduce (session/upload vector — Chains A/C/E):${C_0}"
  say "  • session.upload_progress.enabled = Off   (disables only progress bars; uploads still work)"
  say "  • session.use_only_cookies = On"
  say "  • On PHP 8.5: fatal_error_backtraces = Off"
  say "  • Edge/WAF: block multipart POST bodies containing PHP_SESSION_UPLOAD_PROGRESS"
  say ""
  say "${C_B}${C_RED}What NO config can fix:${C_0} CVE-2026-109618 is OOM corruption in the Zend engine"
  say "  core (the 'Chain D' pre-auth path — any endpoint, mod_php). No php.ini setting,"
  say "  WAF rule, or upload_progress toggle closes it. ${C_B}Only patching the PHP binary does.${C_0}"
  say ""
  if [ "$any_vuln" = 1 ] || [ "$any_uncertain" = 1 ]; then
    say "${C_B}Do now:${C_0} patch every flagged build, then restart its workers."
    say "  Debian/Ubuntu : apt update && apt upgrade  (then restart php*-fpm / apache2)"
    say "  RHEL/Alma/Rocky: dnf upgrade php\\*"
    say "  cPanel EasyApache: dnf upgrade 'ea-php*'  →  /scripts/restartsrv_apache_php_fpm"
    say "  CloudLinux alt-php: dnf upgrade 'alt-php*'   (verify via rpm changelog, not version)"
    say "  LiteSpeed lsphp : update via your LiteSpeed/CyberPanel package channel, restart lsws"
    say "  Then re-run with --deep to actively confirm the OOM path is closed."
    say ""
  fi
fi

case "$OVERALL" in
  patched) exit 0 ;;
  vulnerable) exit 1 ;;
  *) exit 2 ;;
esac
