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
tests/
  conftest.py   Isolated test database setup
  test_assets.py API and validation tests
  test_models.py Database model and relationship tests
  test_openvas_parser.py OpenVAS parser tests
  test_openvas_import.py OpenVAS database import tests
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
