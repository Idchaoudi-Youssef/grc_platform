# Authorized real-lab scan checklist

Use this checklist for a controlled classroom/lab scan only. M10A does not run
the scan or connect to Greenbone automatically.

## Before

- [ ] I own the target or have explicit written authorization to scan it.
- [ ] The approved target IP and time window are recorded.
- [ ] The target is an isolated lab VM, not a public or third-party system.
- [ ] The vulnerable VM is not bridged to an untrusted/public network.
- [ ] Greenbone's default admin password has been changed.
- [ ] GSA is bound to localhost and accessed with HTTPS.
- [ ] Greenbone feeds and scan configurations show ready in GSA.
- [ ] `scripts/check_greenbone_lab.py` has no blocking `FAIL` result.
- [ ] Host-to-target and scanner-to-target reachability were checked separately.
- [ ] The normal `grc.db` and any important lab state are backed up safely.
- [ ] No credential, private XML, VM disk, or backup is staged in Git.

## During

- [ ] The scan target exactly matches the authorized IP/range.
- [ ] I am using a conservative scan configuration suitable for the lab.
- [ ] I monitor target availability and Greenbone container status/logs.
- [ ] I stop immediately if traffic reaches an unintended system or causes harm.
- [ ] I do not run exploitation, patching, shell commands, email, or webhooks from this project.

## After

- [ ] I exported the report XML into a private, Git-ignored location.
- [ ] I validated it first with `scripts/validate_openvas_report.py`.
- [ ] I reviewed parser warnings, unknown hosts, CVSS distribution, and no-CVE findings.
- [ ] I ran `scripts/import_openvas_report.py` without confirmation (dry run).
- [ ] I reviewed dry-run import, scoring, alerts, treatments, warnings, and errors.
- [ ] Only if approved, I repeated the command with `--confirm-import`.
- [ ] I verified the expected scan appeared in the dashboard/reports.
- [ ] I removed temporary exports/logs according to the lab retention policy.
- [ ] I stopped the vulnerable VM or restored its isolated snapshot.
- [ ] I confirmed `git status` contains no confidential or generated lab data.
