# GRC Vulnerability Management API — Milestone 1

This project is a small backend for keeping an **asset inventory**, an important
starting point for vulnerability management. An asset can represent a server,
network device, workstation, or service that your organization needs to protect.

This milestone deliberately contains no frontend, authentication, scanner,
Docker, or PostgreSQL configuration.

## What is included

- **FastAPI** receives HTTP requests and returns JSON responses.
- **Pydantic** checks incoming data before it reaches the database.
- **SQLAlchemy** translates Python operations into database queries.
- **SQLite** stores data locally in `grc.db` without a separate database server.
- **pytest** automatically checks the API's expected and invalid-data behavior.

Each asset has a name, a unique IPv4 or IPv6 address, an asset type, an owner,
business criticality from 1 (lowest) to 5 (highest), exposure of `internal` or
`external`, and an optional description. Timestamps are managed automatically.

Asset type uses a controlled list so that reports do not accidentally treat
values such as `server`, `Server`, and `srv` as three different categories. The
accepted values are `server`, `workstation`, `network_device`, `application`,
`database`, and `other`. The owner is the person or team responsible for the
asset.

## Project structure

```text
app/
  database.py   SQLite connection and request sessions
  models.py     SQLAlchemy tables and relationships
  schemas.py    Pydantic input/output validation
  crud.py       Create, read, update, and delete database operations
  main.py       FastAPI application and URL endpoints
  parsers/
    openvas.py  Secure OpenVAS XML parsing and normalization
  services/
    openvas_import.py Transactional storage of normalized findings
    risk_scoring.py Contextual GRC risk calculation and bulk scoring
    detection_remediation.py Rule-based alerts and automatic treatment tasks
    grc_pipeline.py Atomic end-to-end workflow orchestration
tests/
  conftest.py   Isolated test database setup
  test_assets.py API and validation tests
  test_models.py Database model and relationship tests
  test_openvas_parser.py OpenVAS parser tests
  test_openvas_import.py OpenVAS database import tests
  test_risk_scoring.py Contextual scoring tests
  test_detection_remediation.py Detection and task-creation tests
  fixtures/openvas/ Sanitized XML examples used only by tests
requirements.txt Python dependencies
```

## Core data model

Milestone 2 adds the database foundation needed for later OpenVAS imports. It
does not add API endpoints or import logic yet.

- **Asset** is a system, application, database, or device that the organization
  needs to protect.
- **Scan** records when a scan happened, where it came from, and its finding
  total. Keeping separate scans makes historical trends possible later.
- **Vulnerability** describes the technical weakness, including its optional CVE,
  CVSS score, severity, and source. A CVE is optional because OpenVAS can report
  findings that do not have one.
- **AssetVulnerability** records that one vulnerability was observed on one asset
  in one scan. Its workflow status and future contextual risk score belong here,
  because the same vulnerability can have different business risk on different
  assets.
- **RiskTreatment** records a remediation decision or action, its owner, due date,
  status, evidence, and whether it was generated automatically.
- **Alert** records a noteworthy finding and whether someone has acknowledged it.

The relationships are:

```text
Asset -----------< AssetVulnerability >----------- Vulnerability
                           ^
                           |
                         Scan
                           |
                           +--------< RiskTreatment
                           |
                           +--------< Alert
```

An asset-vulnerability-scan combination can occur only once. SQLite foreign-key
enforcement prevents findings from referring to records that do not exist, and
deleting a parent record removes its dependent finding data.

## OpenVAS XML parser

Milestone 3 adds a standalone parser in `app/parsers/openvas.py`. It accepts an
XML file path, XML bytes, or a readable file-like object and returns three clear
lists:

- normalized findings that are safe for later processing;
- warnings for individual incomplete results;
- fatal errors for reports that could not be parsed safely.

Each normalized finding contains the host, optional port, title, optional
description, numeric CVSS score, derived severity, CVE list, optional solution,
optional threat, and optional NVT OID. IPv4 and IPv6 addresses are normalized,
and valid hostnames are converted to lowercase.

CVE values are extracted from OpenVAS `<cve>` and CVE `<ref>` elements. The
parser accepts comma-separated values, keeps only identifiers matching the
`CVE-YYYY-NNNN...` format, converts them to uppercase, removes duplicates, and
ignores values such as `NOCVE`.

Missing or invalid severity is represented as CVSS `0.0` and informational
severity, with a warning. A result is skipped only when it lacks a usable host or
title, or when those values fail validation. Other valid results in the report
are still returned.

For XML safety, reports containing DTD or entity declarations are rejected
before Python's standard XML parser runs. External entities are therefore never
resolved, and the parser performs no network access.

This parser does **not** write to SQLite or use the SQLAlchemy models. Database
import is deliberately deferred to a later milestone.

## OpenVAS database import

Milestone 4 adds a service in `app/services/openvas_import.py` that accepts an
M3 parse result and a SQLAlchemy session. It performs one atomic database
transaction using this sequence:

1. Reject a parser result that has fatal XML errors and no valid findings.
2. Create one `Scan` record, with source `openvas` unless another source is
   supplied explicitly.
3. Match each finding to an existing asset by its normalized IP address. Unknown
   assets are reported and skipped; the importer never creates assets.
4. Create or reuse vulnerabilities using the identity rules below.
5. Create one unique `AssetVulnerability` relationship for each asset,
   vulnerability, and scan combination.
6. Commit everything together. A database error rolls back the scan and every
   related record created during that import.

For findings containing CVEs, each CVE represents one vulnerability. The same
CVE and source reuse the existing vulnerability record. For a finding without a
CVE, the importer uses `nvt:<OID>` when the NVT OID is present. Otherwise, it
creates a deterministic SHA-256 fingerprint from the normalized title, port,
description, solution, and threat. This stable `technical_id` avoids treating a
title alone as identity.

When an existing vulnerability is reused, its original title, description,
CVSS score, severity, and initial detection time are preserved. Conflicting
incoming metadata is reported as a warning instead of silently overwriting the
trusted record.

Duplicate findings for the same asset and vulnerability inside one scan are
ignored with a warning. Importing the same report again creates a new scan and
new scan-specific relationships, while reusing the vulnerability records.
`first_seen_at` and `last_seen_at` both use that scan's date for now, and
`risk_score` remains null. The scan total records the number of successfully
imported unique `AssetVulnerability` relationships. Therefore, a finding with
multiple CVEs contributes one relationship—and one unit in the scan total—for
each imported CVE.

Every vulnerability must have a stable identity: either `cve_id` or
`technical_id` must be present. SQLite enforces this rule with a check
constraint, even when records are created outside the importer.

The import result reports created/reused vulnerabilities, imported
relationships, skipped findings, unknown assets, warnings, and errors. M4 does
not calculate risk and does not create alerts or treatment actions.

## Contextual GRC risk scoring

Milestone 5 translates technical CVSS severity into business context. The exact
formula is:

```text
raw score = CVSS × business criticality × exposure factor
risk score = (raw score / 75) × 100
```

The denominator is `75` because the theoretical maximum is `10 × 5 × 1.5`.
Internal exposure uses factor `1.0`; external exposure uses `1.5`. The final
score is clamped to 0–100 and rounded to two decimal places before it is stored
on `AssetVulnerability`.

Contextual risk levels are:

| Stored score | Risk level |
|---|---|
| 0.00–24.99 | Low |
| 25.00–49.99 | Medium |
| 50.00–74.99 | High |
| 75.00–100.00 | Critical |

Examples:

1. An external critical server with CVSS `9.0` and criticality `5` has raw score
   `9.0 × 5 × 1.5 = 67.5`, normalized score `90.00`, and **critical** risk.
2. An internal workstation with CVSS `8.5` and criticality `2` has raw score
   `17`, normalized score `22.67`, and **low** risk.
3. An internal database with CVSS `7.5` and criticality `5` has raw score `37.5`,
   normalized score `50.00`, and **high** risk.

The pure calculation function does not use the database. A one-finding service
assigns a score without committing, while the bulk service scores either one
scan or all findings in a single transaction. By default, already scored records
are skipped; `force=True` recalculates them. An invalid individual record is
reported without blocking other valid records. A fatal database error rolls back
every score from that bulk operation.

OpenVAS `Vulnerability.severity` remains the scanner's technical classification.
The M5 `RiskLevel` is a separate contextual business-risk classification. M5
does not create alerts or remediation treatments.

## Rule-based detection and automated remediation

Milestone 6 applies one transparent application-level correlation rule to scored
findings. The stable rule key is `critical_contextual_risk_v1`. It matches only
when all these conditions are true:

- contextual `risk_score` is at least `75.00`;
- asset business criticality is at least `4`;
- finding status is not `fixed`;
- the contextual score is not null.

When the rule matches, the service creates a critical, unacknowledged alert. Its
message contains the asset name and IP, vulnerability title, CVE or technical
identity, and contextual score. It also creates a pending automatic treatment
owned by the asset owner and due seven days after evaluation. The OpenVAS
solution is used when available; otherwise the task recommends reviewing the
service, applying the vendor patch or mitigation, validating the correction, and
scanning again.

Example: an open finding with score `90.00` on a criticality-5 server matches the
rule. The application creates one critical alert and one pending remediation task
due in seven days. It does **not** run a patch command, change the affected
system, isolate the asset, send email, or perform any network action. In this
project, “automated remediation” means automatically creating a tracked GRC task.

Both alerts and treatments have an optional `rule_key`. Manual records use a
null key. Database uniqueness on `(asset_vulnerability_id, rule_key)` prevents
duplicate automatic records, while repeated runs reuse the existing records and
can repair partial state where only the alert or only the treatment exists.

The one-record service flushes but does not commit. The bulk service processes
one scan or all scored findings and commits once. A validation problem on one
finding is reported without blocking the others; a fatal database error rolls
back the complete bulk operation.

## Complete demonstration pipeline

Milestone 7 connects the existing services in this exact order:

```text
OpenVAS XML -> secure parse -> database import -> contextual scoring
            -> critical-risk detection -> alert and remediation task
```

The orchestrator calls the importer, scorer, and detection service without
allowing them to commit independently. It performs one final commit after every
stage succeeds. A fatal database failure during scoring, detection, or the final
commit rolls back the imported scan and all related records. Expected conditions
such as an unknown asset remain warnings and do not block valid findings.

Run the standalone demonstration from the project directory:

```powershell
.\.venv\Scripts\python.exe scripts\demo_pipeline.py
```

The script does not start a web server and does not require Greenbone/OpenVAS. It
uses the sanitized M7 XML fixture and creates two assets labeled as demonstration
data. It deletes and recreates only `scripts/grc_pipeline_demo.db`; it never
deletes or connects to the normal `grc.db`. Running it repeatedly is safe.

Example output:

```text
=== GRC PIPELINE DEMONSTRATION ===
Data label: DEMONSTRATION DATA ONLY
Pipeline success: True
Scan ID: 1
Parsed findings: 3
Findings imported: 3
Vulnerabilities scored: 3
Alerts created: 1
Treatments created: 1
Warnings:
  - Missing severity defaulted to 0.0 for the unknown demonstration host.
  - Unknown asset 192.0.2.72 was skipped.
Prioritized findings:
  1. DEMO - Public customer portal | CVE-2026-7001 | risk=90.00 (critical)
  2. DEMO - Internal analyst workstation | CVE-2026-7002 | risk=22.67 (low)
  3. DEMO - Internal analyst workstation | CVE-2026-7003 | risk=22.67 (low)
```

## Set up and run on Windows PowerShell

The `.venv` virtual environment keeps this project's Python packages separate
from packages installed elsewhere on your computer.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000/docs> for FastAPI's interactive API page. You can
create and inspect assets there without writing a separate client. Use
<http://127.0.0.1:8000/health> for a simple availability check.

Stop the server with `Ctrl+C`.

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Check that the API is running |
| `POST` | `/assets` | Create an asset |
| `GET` | `/assets` | List all assets |
| `GET` | `/assets/{id}` | Read one asset |
| `PATCH` | `/assets/{id}` | Update selected fields |
| `DELETE` | `/assets/{id}` | Delete an asset |

Example body for `POST /assets`:

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

Example partial update for `PATCH /assets/1`:

```json
{
  "owner": "SOC Team",
  "asset_type": "application"
}
```

Only the fields included in a `PATCH` request are changed. All omitted fields
keep their existing values.

Invalid IP addresses, blank owners, unsupported asset types, criticality outside
1–5, and exposure values other than `internal` or `external` return HTTP `422
Unprocessable Entity`. Reusing an IP address returns HTTP `409 Conflict`. A
missing asset returns HTTP `404 Not Found`.

## Run the tests

With the virtual environment activated:

```powershell
python -m pytest
```

Tests use a temporary SQLite database, so they do not change your real `grc.db`.

## Why this matters in vulnerability management

A scanner result is useful only when you know which asset it belongs to and how
important that asset is. Business criticality helps prioritize remediation, and
exposure helps distinguish an internal system from one reachable from the
internet. Later milestones can connect vulnerabilities and scan results to this
asset inventory.
