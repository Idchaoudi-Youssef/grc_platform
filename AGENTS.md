# Project Instructions - GRC Vulnerability Management Platform

## Project objective

Build an open-source cybersecurity GRC application that helps an organization
answer two questions:

1. What vulnerabilities affect its assets?
2. What should be remediated first, based on technical severity and business
   context?

The target end-to-end pipeline is:

`Asset inventory -> OpenVAS XML import -> contextual risk scoring -> rule-based detection -> automatic alert and remediation action -> dashboard/KPIs -> PDF reports`

OpenVAS/Greenbone is an external source of scan data, not the application itself.
The main value of this project is the data model, reliable import, contextual
scoring, prioritization, remediation workflow, visualization, and reporting.

The authoritative functional guide is `docs/Guide_Projet_GRC_v2.pdf`. When code
and the guide appear to disagree, preserve working code, identify the difference,
and resolve it explicitly in the smallest suitable milestone.

## Chosen architecture

Use a modular monolith. Keep one Python codebase and one relational database
until the complete pipeline works. Do not introduce microservices.

The logical flow is:

1. Greenbone/OpenVAS scans only authorized lab targets and exports XML.
2. A Python parser validates and normalizes the XML data.
3. An import service stores scans, vulnerabilities, and asset-vulnerability
   relationships in the database.
4. A scoring service calculates contextual risk on each asset-vulnerability
   relationship, never on the vulnerability alone.
5. A rule service detects critical situations and creates alerts and remediation
   actions without duplicating them.
6. FastAPI exposes the data and workflows through HTTP endpoints.
7. A small Streamlit dashboard reads the API or shared service layer for KPIs.
8. ReportLab and Matplotlib generate technical and executive PDF reports from
   the same trusted data.

Organize backend responsibilities clearly as the project grows:

- `models`: database tables and relationships;
- `schemas`: API input/output validation;
- `crud` or repositories: simple database operations;
- `services`: scoring, importing, detection, and remediation business rules;
- `api` or routers: HTTP endpoints only;
- `tests`: unit, API, parser, and integration tests;
- `dashboard`: the later Streamlit interface;
- `reports`: the later PDF generation code.

The current flat `app/` structure is acceptable for the asset-only milestone.
Split it into submodules only when a new feature makes the split useful.

## Technologies

### Current foundation

- Python 3.10+
- FastAPI for the backend API and automatic OpenAPI documentation
- Pydantic for request and response validation
- SQLAlchemy 2 for database access and relationships
- SQLite for early development
- pytest and FastAPI TestClient/httpx for automated tests
- Uvicorn as the local ASGI server

### Add only in the milestone that needs them

- `lxml` or Python ElementTree for OpenVAS XML parsing
- Greenbone Community Edition/OpenVAS as the external scanner
- Manual XML export first; `python-gvm` automation later and only if useful
- Streamlit for a deliberately small dashboard
- ReportLab and Matplotlib for PDF reports and embedded charts
- Docker Compose for Greenbone and final reproducibility
- PostgreSQL only after the SQLite pipeline is working and migration is justified

Prefer free and open-source components. Pin direct Python dependencies in
`requirements.txt` and explain each newly added dependency in the README.

## Core data model target

Keep the following responsibilities from the guide:

- `Asset`: name, IP address, type, business criticality (1-5), exposure
  (`internal`/`external`), owner, and timestamps.
- `Vulnerability`: CVE identifier when present, CVSS score, title, description,
  severity, detection time, and source.
- `Scan`: scan date, source, totals, and import time for history and trends.
- `AssetVulnerability`: asset/vulnerability relationship, workflow status, and
  contextual `risk_score`.
- `RiskTreatment`: remediation action, owner, due date, state, resolution,
  evidence, and whether it was created automatically.
- `Alert`: rule-generated level, message, time, and acknowledgement state.
- `FrameworkControl`: optional extension only after the base pipeline is done.

Protect referential integrity with foreign keys and useful uniqueness rules.
Make repeated imports and repeated rule evaluation idempotent: they must not
silently create duplicate findings, alerts, or actions.

## Risk and automation rules

The baseline risk idea from the guide is:

`risk = CVSS (0-10) * asset criticality (1-5) * exposure factor`

Use exposure factor `1.0` for internal assets and `1.5` for external assets,
then normalize consistently to 0-100 and classify the result as Low, Medium,
High, or Critical. Before implementing scoring, document the exact normalization
and level thresholds and lock them with unit tests; the guide's rounded examples
must not be treated as a precise formula specification.

Baseline detection/remediation behavior:

- detect a contextual score at or above the documented critical threshold
  (guide baseline: 80) on a major asset (criticality at least 4);
- create an alert automatically;
- create a high-priority treatment action automatically;
- assign it to the asset owner when possible;
- optionally notify by email/webhook in a later step;
- optionally detect a newly appeared critical finding compared with the prior
  scan.

Describe this honestly as rule-based correlation and automated remediation, or
lightweight SOAR behavior. Never call it AI-based real-time network detection.

## Development rules

1. Work in small, testable milestones. Finish one vertical slice before starting
   several partially complete modules.
2. Preserve working behavior. Do not rebuild, delete, or broadly refactor code
   merely to match a preferred structure.
3. Before changing a database table, state how the existing SQLite database will
   be migrated or safely recreated. Never discard user data without permission.
4. Write or update tests with every behavior change. Run the full test suite
   before marking a milestone complete.
5. Test invalid and imperfect input, especially missing CVEs, multiple CVEs in one
   result, malformed XML, invalid CVSS values, unknown hosts, and repeated imports.
6. Keep FastAPI route functions thin. Put calculations, parsing, correlation, and
   automation in plain Python service functions that are easy to test.
7. Use type hints and short docstrings where they improve understanding. Choose
   descriptive names over abbreviations.
8. Keep configuration in one obvious place. Introduce environment variables only
   when configuration actually differs between environments; never commit secrets.
9. Keep README setup, run, test, and demonstration instructions current after
   every milestone.
10. Scan only systems owned by or explicitly authorized for the lab. Prefer an
    isolated network with Metasploitable 2 or DVWA. Change Greenbone's default
    credentials immediately.
11. Commit generated database files, scan exports containing sensitive data,
    secrets, caches, and virtual environments to neither Git nor documentation.
    Sanitized XML fixtures for tests are allowed.
12. Do not add authentication, complex authorization, cloud infrastructure,
    microservices, queues, or frontend frameworks unless a later approved
    milestone clearly requires them.

## Simplicity and teaching rules

The primary developer is a cybersecurity student, not a software-development
specialist. Optimize for learning and traceability:

- Prefer direct, readable Python over clever abstractions and design patterns.
- Introduce one new concept at a time and explain why it is needed in plain
  language.
- Keep functions short and make business rules visible in named constants or
  small functions.
- Include realistic cybersecurity examples in tests and documentation.
- Explain the flow from HTTP request to validation, database operation, and
  response when adding an endpoint.
- Explain the security/GRC meaning of a feature, not only its implementation.
- Avoid premature generic frameworks, dependency injection layers, async database
  code, and performance optimization.
- A small complete and demonstrable pipeline is better than a sophisticated but
  unfinished platform.

## Milestones

### M0 - Existing foundation and asset CRUD (completed)

- Virtual environment and pinned requirements
- FastAPI application, health endpoint, SQLite/SQLAlchemy configuration
- Asset CRUD API
- IPv4/IPv6, criticality, and exposure validation
- Isolated automated API tests and introductory README

### M1 - Complete the guide's asset inventory (completed)

- Confirm or initialize a valid Git repository before changing application code
- Add the missing asset `type` and `owner` fields
- Decide and document required/optional behavior and length validation
- Handle the existing SQLite schema safely
- Update CRUD tests and README examples

### M2 - Add the core relational schema (completed)

- Add `Scan`, `Vulnerability`, `AssetVulnerability`, `RiskTreatment`, and `Alert`
  models with enums, constraints, relationships, and timestamps
- Add focused model/database tests
- Do not build every API endpoint yet

### M3 - Build and test the OpenVAS XML parser (completed)

- Add small sanitized XML fixtures
- Extract host, title, CVSS, zero/one/multiple CVEs, and scan metadata
- Normalize IPv4/IPv6 values and handle missing/malformed fields clearly
- Keep parsing independent of both FastAPI and the database

### M4 - Import one scan end to end (completed)

- Add an import service driven by the CLI scripts (no HTTP upload endpoint yet)
- Store the scan and findings and link findings to assets by normalized IP
- Report unknown hosts instead of silently dropping them
- Make re-import behavior explicit and idempotent

### M5 - Implement contextual risk scoring (completed)

- Define normalization and Low/Medium/High/Critical thresholds precisely
- Calculate and store risk on `AssetVulnerability`
- Add boundary-focused unit tests and prioritized ordering in the services,
  dashboard, and reports (no HTTP result endpoint yet)

### M6 - Implement rule-based detection and remediation (completed)

- Evaluate findings after import/scoring
- Create idempotent critical alerts and automatically generated treatments
- Keep alert acknowledgement and treatment state in the database; exposing
  write endpoints for them is not implemented yet
- Add optional notification only after local rule behavior is reliable

### M7 - Complete a one-case vertical pipeline (completed)

- Demonstrate one asset, one sanitized/real lab scan, one score, one alert, and one
  remediation action through the API
- Add an integration test covering the entire flow
- Prepare the legal isolated Greenbone/Metasploitable lab procedure

### M8 - Add a minimal Streamlit dashboard (completed)

- Show risk by level, critical open count, unacknowledged alerts, treatment rate,
  top risky assets, and risk trend
- Add useful filters without turning the dashboard into a large frontend project

### M9 - Generate GRC PDF reports (completed)

- Generate a technical findings report
- Generate a one-page executive summary from the same data
- Include readable charts and verify rendered PDFs visually

### M10A - Safe manual Greenbone/OpenVAS lab integration (completed)

- Document the official Greenbone Community Containers setup without vendoring
  or modifying its Compose file
- Keep the vulnerable target isolated and require explicit scan authorization
- Add non-destructive Docker, HTTPS, target, and disk preflight checks
- Validate exported XML with the existing secure parser and no database access
- Dry-run the existing pipeline against a temporary SQLite backup by default
- Require `--confirm-import` before the existing database can be changed

### M10B - Optional scanner automation and final verification (deferred)

- Consider GMP/python-gvm only after the manual M10A workflow is reviewed
- Do not automatically create targets, schedules, credentials, or scans without
  a separately approved design and safety boundary
- Consider PostgreSQL only if the complete pipeline demonstrates a real need
- Run the final authorized end-to-end demonstration and update documentation

### Optional extensions - only after M10

- ISO 27001/NIST CSF control mapping
- EPSS or CISA KEV enrichment
- OpenSCAP configuration compliance
- Analyst/executive roles and permissions
- A narrowly scoped, honestly described AI-assisted summary

## Limitations and scope

- This is initially an educational/lab platform, not a production Greenbone
  deployment or enterprise GRC suite.
- Detection is application-level correlation of scan results, not live network
  monitoring and not an IDS/IPS.
- Automatic remediation means creation and tracking of alerts/actions. It does
  not initially patch or isolate real systems automatically.
- SQLite is the development database; PostgreSQL migration is deferred.
- Manual OpenVAS XML import comes before GMP automation.
- Streamlit is the preferred minimal interface; React is outside the current
  scope.
- Full ISO 27001 compliance management, Zero Trust networking, OpenSCAP, broad
  AI features, enterprise authentication, and production deployment are outside
  the base pipeline.
- Greenbone Community Edition is suitable for this authorized lab/demo context;
  its feed synchronization and disk requirements must be planned separately from
  application development.
