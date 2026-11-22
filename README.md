# ASSETWISE AI

**An Uncertainty-Aware Framework for Vulnerability Prioritisation Under Incomplete and Unreliable Asset Context**

A local college demonstration prototype exploring how missing, stale and conflicting asset-context data can affect vulnerability remediation rankings.

## Quick start (Windows)

1. Install Python 3.10 or newer.
2. Extract the ZIP.
3. Double-click `run_windows.bat`.
4. Open http://127.0.0.1:8000 in your browser.

## Quick start (macOS/Linux)

```bash
chmod +x run_unix.sh
./run_unix.sh
```

Open http://127.0.0.1:8000. API documentation is available at http://127.0.0.1:8000/docs.

## Included features

- Vulnerability register with CVSS, EPSS and KEV fields.
- Synthetic asset inventory.
- Missing/stale/conflicting data-quality indicators.
- Scenario generator with configurable degradation and random seed.
- CVSS, EPSS, KEV, combined and context-aware demonstration rankings.
- Scenario-based Top-K inclusion probability and rank stability metrics.
- Analyst review queue and decision history.
- Degradation sensitivity experiment.
- Interactive dark-themed web dashboard.

## Data integrity and research limitations

The included asset inventory is synthetic. Seed vulnerability rows are illustrative demonstration records; verify every CVE, score, EPSS snapshot, KEV status, affected product and retrieval date against authoritative sources before using them in a research paper. The application does not currently download live NVD, FIRST EPSS or CISA KEV data.

The context-aware score is a transparent, illustrative formula, not an industry standard or validated risk model. Scenario intervals are empirical ranges, not calibrated confidence intervals. The synthetic source-conflict flag is a demonstration fixture, not evidence of a real multi-source conflict.

This application is a college research prototype, not a production vulnerability management system. It does not connect to or remediate real infrastructure.

## Architecture

- FastAPI backend (`app/main.py`)
- SQLite database (`data/assetwise.db`, created on first run)
- Vanilla JavaScript/CSS dashboard (`static/`)
- Reproducible scenario simulation (Python `random.Random(seed)`)

## API endpoints

- `GET /api/health`
- `GET /api/summary`
- `GET /api/assets`
- `POST /api/assets`
- `GET /api/vulnerabilities`
- `GET /api/rankings`
- `GET /api/simulate?degradation=0.3&scenarios=100&seed=42&top_k=5&defect=mixed`
- `GET /api/reviews`
- `POST /api/reviews`
- `GET /api/experiments`

## Suggested live demo (5–7 minutes)

1. Overview: show vulnerability and asset counts.
2. Vulnerabilities: explain CVSS, EPSS and KEV fields.
3. Asset inventory and Data Quality: inspect stale and synthetic conflict flags.
4. Scenario Simulator: run 30% mixed degradation over 100 scenarios.
5. Ranking Stability: explain Top-K inclusion probability, median rank and rank range.
6. Human Review: record a verification request.
7. Experiments: show sensitivity to degradation.
8. Methodology: explain the illustrative score and research limitations.

## Project structure

```text
ASSETWISE_AI/
├── app/
│   └── main.py
├── static/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── data/
│   └── (SQLite database generated at runtime)
├── docs/
│   ├── project_report.md
│   ├── presentation_outline.md
│   ├── demo_script.md
│   └── research_methodology.md
├── tests/
│   └── test_api.py
├── requirements.txt
├── run_windows.bat
└── run_unix.sh
```
