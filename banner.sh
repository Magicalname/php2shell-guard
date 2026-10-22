#!/usr/bin/env bash
# banner.sh — shared ASCII banner for the php2shell-guard toolkit.
# Sourced by the audit/forensics/fleet scripts. Prints only to an interactive
# terminal: suppressed automatically under --json, pipes, and fleet runs so it
# never corrupts machine-readable output.
#
# Usage inside a script:
#   source "$(dirname "$0")/banner.sh"
#   p2s_banner        # respects $JSON and TTY; no-op when output isn't a terminal
#
# License: MIT

p2s_banner() {
  # suppress when: JSON mode, not a TTY (piped/redirected), or P2S_NOBANNER set
  [ "${JSON:-0}" = 1 ] && return 0
  [ -n "${P2S_NOBANNER:-}" ] && return 0
  [ ! -t 1 ] && return 0

  local c g y r0
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    c=$'\033[36m'; g=$'\033[32m'; y=$'\033[33m'; r0=$'\033[0m'
  else c=""; g=""; y=""; r0=""; fi

  printf '%s' "$c"
  cat <<'ART'
        .-"""-.
       /  _ _  \
      |  (o|o)  |      ┌─┐┬ ┬┌─┐┌─┐┌─┐┬ ┬┌─┐┬  ┬  ┌─┐┬ ┬┌─┐┬─┐┌┬┐
      |  __V__  |      ├─┘├─┤├─┘┌─┘└─┐├─┤├┤ │  │  │ ┬│ │├─┤├┬┘ ││
      |,-'   `-,|      ┴  ┴ ┴┴  └─┘└─┘┴ ┴└─┘┴─┘┴─┘└─┘└─┘┴ ┴┴└──┴┘
     /(  \___/  )\        php2shell-guard · shields up
    |  \  `-'  /  |
     \  `-----'  /
    __`._____.'__
   [___|  |  |___]
    [#] |  | [#]
        |__|
ART
  printf '%s' "$r0"
  printf '%s   CVE-2026-109618 / CVE-2026-109619%s\n' "$y" "$r0"
  printf '%s   read-only defensive audit · no exploit code · fleet-ready%s\n' "$g" "$r0"
  printf '%s   Built with letters, numbers, ❤️  and Claude%s\n\n' "$c" "$r0"
}
