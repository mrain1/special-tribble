# CyberCNS Vulnerability Prioritisation Toolkit

This repository contains a small Python toolkit that mirrors the logic from the
Marks Custom Vulnerability Database spreadsheet and turns it into something that
can be automated. The goal is to query CyberCNS' V4 API, score each
vulnerability with customisable logic, store the results in SQLite and track
remediation progress over time.

## Features

- **API ingestion** – fetch paginated vulnerability data from CyberCNS.
- **Configurable risk calculations** – tune severity weights, CVSS influence,
  exploit and patch multipliers, aging penalties and asset criticality impact.
- **Automatic remediation timelines** – assign target dates per risk tier so you
  can track whether items are trending overdue.
- **SQLite persistence** – keep a local database of the prioritised queue as
  well as a history of status changes.
- **Command line utilities** – synchronise data, inspect the backlog and update
  remediation status without leaving the terminal.

## Getting started

1. Create and activate a Python 3.10+ virtual environment.
2. Install dependencies:

   ```bash
   pip install -e .
   ```

3. Copy `config.example.yaml` to `config.yaml` and populate the API token,
   server URL and (optionally) tweak the scoring weights to match your existing
   spreadsheet.

4. Run the synchronisation command:

   ```bash
   python -m vuln_manager.cli --config config.yaml sync
   ```

   A SQLite database will be created at the path specified in the config
   (`data/vulnerabilities.sqlite3` by default) and populated with the scored
   vulnerabilities.

5. Inspect the prioritised list:

   ```bash
   python -m vuln_manager.cli --config config.yaml list --status open --limit 20
   ```

6. Update remediation status as work progresses:

   ```bash
   python -m vuln_manager.cli --config config.yaml update-status VULN-ID closed --note "Patched in KB1234"
   ```

## Configuration

The YAML configuration is split into four sections:

- `api` – base URL, token, endpoint path, page size and optional query
  parameters passed to every request.
- `database` – file location for the SQLite database. The parent directory is
  created automatically.
- `scoring` – knobs that influence the computed risk score. Adjust severity
  overrides, CVSS weighting, exploit/patch multipliers, age breakpoints and
  asset criticality contribution to mirror the calculations used in the custom
  spreadsheet.
- `timelines` – number of days allowed for each risk tier; used to automatically
  populate the `target_date` column in the database.

All values can be tweaked without changing any Python code – re-run the `sync`
command after editing the config to recalculate scores.

## Data model

The SQLite database keeps two tables:

- `vulnerabilities` – the current snapshot, including computed `risk_score`,
  `risk_level`, remediation target date and a JSON blob with the reason
  breakdown (`risk_reasons`).
- `remediation_history` – a simple audit log tracking every status change along
  with an optional note.

The `vulnerabilities` table uses the CyberCNS vulnerability identifier as the
primary key so re-running a synchronisation updates existing records in place.

## Extending the scoring logic

The `RiskCalculator` class inside `src/vuln_manager/scoring.py` is the only
component that touches the formula. To introduce new factors (for example,
exposure windows, exploit prediction or business unit overrides) you can add new
fields to the configuration and extend the calculator accordingly. Tests in
`tests/test_scoring.py` demonstrate how the class works in isolation.

## Running tests

```bash
python -m pytest
```

The tests cover the scoring rules and the persistence layer. Add more tests as
new rules or API transformations are introduced.

## Caveats

- The repository does not ship with real credentials or production data. All
  API interaction happens against the endpoint defined in `config.yaml`.
- The API schema can evolve; if CyberCNS changes field names, adjust the
  `_record_to_vulnerability` helper in `src/vuln_manager/sync.py`.
- The CLI intentionally stays simple – hook the database into your BI tooling or
  automation platform as needed.
