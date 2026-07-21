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
tests/
  conftest.py   Isolated test database setup
  test_assets.py API and validation tests
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
