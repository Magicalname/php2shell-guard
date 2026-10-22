# php2shell-guard

**Defensive audit & hardening toolkit for CVE-2026-109618 / CVE-2026-109619 (php2shell).**

Two critical pre-auth PHP RCE flaws, CVSS 9.2, disclosed and patched on 2026-10-21.
This toolkit tells you — across a whole fleet — **which PHP builds are exposed, what
config can and cannot close, and whether a host shows signs of having been hit.**

It is **read-only and non-exploitative**. It does not contain, ship, or run exploit
code. It reads version + configuration state and searches for post-compromise
indicators. Run it only on systems you own or are authorized to audit.

---

## Why another tool

Most "check" scripts run `php -v` once and compare the number. On real hosting
infrastructure that is wrong in three ways, and this toolkit fixes all three:

1. **Many PHP builds per host.** cPanel, CloudLinux, LiteSpeed and Plesk servers run
   8–15 PHP versions in parallel. One patched, twelve not. This tool enumerates
   every build under `/opt/cpanel/ea-php*`, `/opt/alt/php*`, `/usr/local/lsws/lsphp*`,
   `/opt/plesk/php/*` and Remi/system paths — not just `$PATH`.

2. **Backports keep the old version string.** `ea-php81` stays `8.1.34-5`, CloudLinux
   `alt-php` and Debian/RHEL backport the fix without bumping the number. For those
   builds the tool checks the **package changelog for the CVE**, which is the only
   reliable test — not the version.

3. **"Mitigated" ≠ "fixed".** Disabling `session.upload_progress` and adding WAF rules
   only reduces the session/upload vector. CVE-2026-109618 is OOM corruption in the
   **Zend engine core** — no php.ini setting closes it. The tool states this per host,
   so nobody mistakes hardening for a fix.

4. **Tells you if the fix is already waiting.** For every build that isn't confirmed
   patched, the audit checks your repos (read-only, no install) and prints the exact
   command — `» UPDATE AVAILABLE → run: dnf upgrade alt-php83` — or tells you plainly
   that **no fix is in your repos** and you need a branch switch or vendor backport.
   "Available" means a newer package exists; the tool reminds you to re-check the
   changelog after installing to confirm the fix actually landed.

---

## Scripts

| Script | What it does |
|---|---|
| `php2shell-audit.sh` | Audits every PHP build on one host. Version + changelog + config, chain-aware advice. |
| `php2shell-forensics.sh` | Read-only post-compromise IOC scan: attack strings in logs, webshells, poisoned session files, persistence, outbound signals. |
| `php2shell-fleet.sh` | Runs the audit (and optionally forensics) across a host list over SSH, prints a triage summary + CSV. |
| `detection/` | Ready-made Suricata/Snort, Sigma and ModSecurity rules for the primary attack vector. |

## Quick start

```bash
# One host
./php2shell-audit.sh                 # human-readable
./php2shell-audit.sh --json          # machine-readable
./php2shell-audit.sh --deep          # + optional active OOM confirmation (see caveat)

# Did this host get hit?
sudo ./php2shell-forensics.sh --webroot=/var/www

# Whole fleet
./php2shell-fleet.sh --hosts hosts.txt --user ops --out report.csv
./php2shell-fleet.sh --hosts hosts.txt --forensics        # also IOC-scan each host
```

`hosts.txt`: one target per line — `host`, `user@host`, or `user@host:port`.
`#comments` and blank lines ignored.

## Exit codes

- `audit`: `0` all patched · `1` ≥1 vulnerable · `2` uncertain · `3` no PHP found
- `forensics`: `0` no IOCs found · `1` IOCs found
- `fleet`: `1` if any host is vulnerable (so cron/CI can alert)

---

## Reading the results honestly

- **`uncertain` on a backport build** means the version is below upstream *and* the
  changelog wasn't readable. Confirm with
  `rpm -q --changelog <pkg> | grep -m1 CVE-2026-109618` — **empty output = still vulnerable.**
- **`--deep` only confirms, never clears.** A crash signature proves unpatched; a
  "survived" result does **not** prove patched (a lightweight CLI probe can't reproduce
  the full exploit). Version/changelog stays the authority.
- **Forensics "no IOCs found" is not "proven clean."** A capable attacker wipes logs
  and hides shells. If you had an exposed window, patch, rotate secrets, keep watching.
- **Exfiltration cannot be proven from one host.** The forensics scan flags *suspicious
  outbound signals* for a human to chase — it never claims "0 bytes left."

## Fixed versions (upstream)

| Branch | Fixed | Branch | Fixed |
|---|---|---|---|
| 8.5 | 8.5.12 | 8.3 | 8.3.36 |
| 8.4 | 8.4.27 | 8.2 | 8.2.35 |

PHP 8.1 and older: no php.net release — use a distro/LTS/vendor backport and verify it
references the CVE. **Patching the binary is the only complete fix.**

## Security of the toolkit itself

A tool that runs as root across a fleet must not be a liability. This one is:

- `shellcheck`-clean at warning level across all scripts.
- Forensics parses attacker-influenced data (log filenames, session contents) with
  NUL-delimited `while read`, not unquoted word-splitting — safe on a host you are
  already treating as possibly compromised.
- Fleet runner **rejects** host entries that look like ssh options (`-o…`) or contain
  shell metacharacters, and passes `--` before every target (no argument injection).
- Fleet runner ships each script to a **random** `mktemp` dir on the target and cleans
  up, avoiding predictable-name symlink/TOCTOU swaps on multi-user hosts.
- Everything is read-only: no file is modified, quarantined, or deleted on any host.

## License

MIT. For authorized security testing and defensive operations only.

---

_Built with letters, numbers, ❤️ and Claude._
