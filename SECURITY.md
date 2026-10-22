# Security Policy

## Scope

php2shell-guard is a **defensive** toolkit. It is read-only: it does not exploit,
modify, quarantine, or delete anything on any host. It contains no exploit code for
CVE-2026-109618 / CVE-2026-109619 and will not be extended to.

## Responsible use

Run the scripts only on systems you own or are explicitly authorized to audit. The
fleet runner connects over your own SSH credentials — you are responsible for where
you point it.

## Reporting a vulnerability in this tool

A security tool that itself has a flaw is worth reporting. If you find one — command
injection, an unsafe file operation, a way to make the fleet runner act on an
untrusted host entry — please open a GitHub issue marked **[security]**, or contact
the maintainer directly before public disclosure if the issue is serious.

## What this tool deliberately does NOT claim

- "No indicators found" is **not** proof a host is clean.
- An available package update is **not** proof the fix is present until the changelog
  confirms it post-install.
- Exfiltration cannot be proven from a single host; the forensics module only surfaces
  leads for a human.

These limits are stated in each script and the README on purpose. Please keep them in
any fork — a defensive tool that overstates certainty does more harm than good.
