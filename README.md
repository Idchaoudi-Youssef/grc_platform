# GRC Vulnerability Management Platform

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Stack](https://img.shields.io/badge/stack-FastAPI%20|%20SQLAlchemy%20|%20SQLite%20|%20Streamlit-informational)

> A scanner tells you what is broken. A GRC platform tells you **what to fix first**.

OpenVAS gives you a list of CVSS numbers. That list is not a plan. This project
turns a raw scan export into a prioritized remediation backlog by combining
technical severity with **business context**: how critical the asset is and
whether it is exposed to the internet.

```
  Asset inventory
        │
        ▼
  OpenVAS XML export ──► secure parser ──► transactional import
        │                                        │
        │                                        ▼
        │                          contextual risk scoring
        │                       (CVSS × criticality × exposure)
        │                                        │
        │                                        ▼
        │                            rule-based detection
        │                                        │
        │                                        ▼
        │                      critical alert + remediation task
        │                                        │
        ▼                                        ▼
     SQLite  ◄──────────────────────────►  Streamlit dashboard
                                                │
                                                ▼
                                executive + technical PDF reports
```

---

## Why contextual risk?

The same CVE means different things on different machines. A CVSS 9.8 on an
isolated analyst workstation is not the same problem as a CVSS 9.8 on an
internet-facing payment server.

```
raw  = CVSS × business_criticality × exposure_factor
risk = (raw / 75) × 100        # 75 = 10 × 5 × 1.5 (theoretical max)
```

`exposure_factor` is `1.0` internal and `1.5` external. Scores are clamped to
0–100 and rounded to two decimals.

| Stored score | Risk level |
|---|---|
| 0.00 – 24.99 | Low |
| 25.00 – 49.99 | Medium |
| 50.00 – 74.99 | High |
| 75.00 – 100.00 | Critical |

The risk score lives on the **asset–vulnerability relationship**, never on the
vulnerability itself, because the same flaw carries different business weight
on different assets.

**Detection rule** `critical_contextual_risk_v1` fires when a finding scores
≥ 75.00 on an asset with criticality ≥ 4 and is not already fixed. It creates a
critical alert and a tracked remediation task owned by the asset owner, due in
7 days.

---

## Quick start

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Interactive API docs → <http://127.0.0.1:8000/docs> · health check → `/health`

Run the full pipeline with no server and no scanner:

```powershell
python scripts\demo_pipeline.py
```

Launch the read-only dashboard:

```powershell
python scripts\prepare_dashboard_demo.py
streamlit run dashboard\streamlit_app.py
```

---

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Availability check |
| `POST` | `/assets` | Create an asset |
| `GET` | `/assets` | List assets |
| `GET` | `/assets/{id}` | Read one asset |
| `PATCH` | `/assets/{id}` | Update selected fields |
| `DELETE` | `/assets/{id}` | Delete an asset |

```json
{
  "name": "Internet-facing web server",
  "ip_address": "203.0.113.10",
  "asset_type": "server",
  "owner": "Infrastructure Team",
  "business_criticality": 5,
  "exposure": "external",
  "description": "Hosts the public customer portal"
}
```

Invalid IP, blank owner, unsupported asset type, criticality outside 1–5, or
bad exposure → `422`. Duplicate IP → `409`. Missing asset → `404`.

> The scan pipeline currently runs through the CLI scripts, not over HTTP.
> Importing an XML report through the API is not implemented yet.

---

## What's inside

```
app/
  main.py                    FastAPI app and routes
  models.py                  SQLAlchemy tables
  schemas.py                 Pydantic validation
  crud.py                    Asset database operations
  parsers/openvas.py         Secure XML parsing (no DB access)
  services/
    openvas_import.py        Transactional import
    risk_scoring.py          Contextual risk engine
    detection_remediation.py Rules, alerts, remediation tasks
    grc_pipeline.py          One-transaction orchestration
  reports/                   Executive + technical PDFs
  lab/                       Greenbone preflight and safe import
dashboard/                   Read-only Streamlit UI
scripts/                     Demo, reports, validation, import CLIs
tests/                       205 tests + sanitized XML fixtures
```

**Data model**

```
Asset ────────< AssetVulnerability >──────── Vulnerability
                      ▲
                      │
                    Scan
                      │
                      ├──< RiskTreatment
                      └──< Alert
```

SQLite enforces foreign keys and uniqueness, so a repeated import or a repeated
rule run never creates duplicate findings, alerts, or tasks.

---

## Reports

Three PDFs are generated from the same read-only database snapshot:

- **Executive report** — one page, management view of posture and KPIs.
- **Technical summary** — exactly three pages, top 10 priorities, roadmap.
- **Findings appendix** — complete evidence, one card per finding.

```powershell
python scripts\generate_reports.py `
  --database scripts\grc_dashboard_demo.db `
  --output-dir output\pdf `
  --organization "Demo Organization" `
  --source-finding-count 3
```

A scanner result with multiple CVEs becomes several asset–vulnerability
relationships, so the stored count and the original scanner count differ.
Reports never guess the scanner count — pass `--source-finding-count` if you
know it.

---

## Lab integration (safe by default)

Greenbone/OpenVAS stays external. This project only consumes a manually
exported XML report.

```powershell
python scripts\check_greenbone_lab.py --help          # non-destructive checks
python scripts\validate_openvas_report.py report.xml  # parse only, no DB
python scripts\import_openvas_report.py report.xml --database .\grc.db
```

The import command **dry-runs against a temporary database copy** by default.
Writing to your real database requires the explicit `--confirm-import` flag.

See [`docs/lab/greenbone_setup.md`](docs/lab/greenbone_setup.md) for the
container setup and [`docs/lab/real_scan_checklist.md`](docs/lab/real_scan_checklist.md)
for the authorized-scan checklist. Only scan systems you own or are explicitly
authorized to test, on an isolated network.

---

## Tests

```powershell
python -m pytest
```

Tests run against a temporary SQLite database and never touch your real
`grc.db`. Fixtures include malformed XML, XXE attempts, missing CVEs, multiple
CVEs, and invalid CVSS values.

---

## Honest limitations

This is an educational and lab platform, not a production GRC suite.

- **Not live detection.** It correlates imported scan results, offline. It is
  not an IDS/IPS and does not monitor the network.
- **"Automated remediation" means tracked task creation.** Nothing is patched,
  isolated, or exploited automatically.
- **No authentication.** Do not expose it to an untrusted network.
- **SQLite only.** PostgreSQL and scanner API automation are deferred.
- **Greenbone remains manual.** XML in, XML out.

---

## License

MIT — see [LICENSE](LICENSE).
