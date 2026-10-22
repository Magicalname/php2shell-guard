# Detection rules

Edge/IDS/SIEM rules for CVE-2026-109618 / CVE-2026-109619. They target the primary
php2shell vector — `PHP_SESSION_UPLOAD_PROGRESS` in a multipart POST body — plus a
couple of secondary indicators (502 bursts from OOM crashes, webshell-style params).

| File | Format | Deploy |
|---|---|---|
| `php2shell.rules` | Suricata / Snort | drop into your `rules/` dir, reload |
| `php2shell.yaml` | Sigma (3 rules) | convert with `sigma convert` for your SIEM |
| `modsecurity.conf` | ModSecurity v2/v3 | include in Apache/Nginx WAF config |

## Important caveats

- **Test before you block.** Run every rule in alert/detection-only mode first and
  watch for false positives against your real traffic.
- **This is a mitigation, not a fix.** Blocking the upload_progress field closes the
  session/upload vector (Chains A/C/E), not the Zend-core OOM path (CVE-2026-109618,
  "Chain D"). Only patching the PHP binary closes that. Use these rules to buy time.
- **SID / rule IDs** are in local/experimental ranges — renumber to avoid clashing
  with your existing ruleset.

## Fastest single action

If you deploy one thing: block multipart POST bodies containing
`PHP_SESSION_UPLOAD_PROGRESS` at your WAF. Near-zero legitimate use, covers the primary
attack vector for both CVEs.
