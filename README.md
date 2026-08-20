# ReconW — Security Reconnaissance Pipeline Orchestrator

**ReconW** is a local-first, automated 5-stage reconnaissance and asset discovery pipeline orchestrator. It executes industry-standard Go reconnaissance tools in sequence, enforces strict in-scope/out-of-scope boundaries, tracks all provenance in an embedded SQLite database, calculates risk-prioritization scores, and generates an interactive, self-contained HTML report.

---

## Features

- **Automated 5-Stage Reconnaissance Pipeline:**
  1. **Stage 1 (Subfinder):** Passive subdomain discovery across multiple OSINT sources.
  2. **Stage 2 (DNSx):** Fast multi-record DNS resolution (`A`, `AAAA`, `CNAME`) & live host filtering.
  3. **Stage 3 (HTTPx):** Probing HTTP/HTTPS services, status codes, titles, technology detection & screenshots.
  4. **Stage 4 (Katana):** Active shallow crawling for hidden endpoints, JavaScript files, and API routes.
  5. **Stage 5 (Prioritize):** Pure Python explainable scoring engine (+30 Admin/Auth, +20 Sensitive APIs, +10 401/403, etc.) ranking targets from **Critical** to **Info**.
- **Audit Provenance & SQLite Storage:** 8-table relational schema logging every command, exit code, timestamp, and finding.
- **Interactive Offline HTML Dashboard:**
  - Client-side search & filtering by severity band (**Critical**, **High**, **Medium**, **Low**, **Info**).
  - Collapsible scoring rule breakdown.
  - Client-side JSON export button.
- **Cross-Platform:** Works on **Linux (Kali Linux, Ubuntu, Debian)**, **macOS**, and **Windows**.

---

## Prerequisites

ReconW orchestrates the following ProjectDiscovery tools. Make sure they are installed in your `PATH`:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

*Ensure `$HOME/go/bin` is in your environment `PATH`.*

---

## Installation

### Option A: Standard Pip (Linux / macOS / Windows)
```bash
git clone https://github.com/Toxkay/reconw-orchestrator.git
cd reconw-orchestrator
pip install .
```

### Option B: Kali Linux (Using `pipx` or `--break-system-packages`)
```bash
# Recommended for Kali:
sudo apt install -y pipx && pipx ensurepath
pipx install .

# Or direct install:
pip install . --break-system-packages
```

### Option C: Development Setup (Using Poetry)
```bash
poetry install
poetry run pytest
```

---

## Usage

### 1. Verify Dependencies
Check that all external Go binaries are installed and detected:
```bash
reconw doctor
```

### 2. Run Full Reconnaissance
Provide your in-scope targets file and optional out-of-scope exclusions:
```bash
reconw run -i inscope.txt -o outscope.txt
```

#### CLI Options:
| Flag | Description | Default |
| :--- | :--- | :--- |
| `-i, --inscope` | **Required.** Path to in-scope targets text file | — |
| `-o, --outscope` | Path to out-of-scope exclusion rules file | `None` |
| `-d, --db` | SQLite database file location | `reconw.db` |
| `-r, --reports-dir` | Directory to save generated HTML reports | `reports/` |
| `--no-crawl` | Skip Stage 4 active crawling (Katana) | `False` |
| `--no-report` | Skip generating the HTML report | `False` |

---

### 3. View Historical Runs
List previous reconnaissance runs saved in the SQLite database:
```bash
reconw list-runs
```

### 4. Regenerate HTML Report
Generate or re-render an interactive HTML report from any past database run without rescanning:
```bash
reconw report -r 1 -o my_report.html
```

---

## Scope File Examples

### `inscope.txt` (Targets)
```text
example.com
*.example.com
target-app.org
```

### `outscope.txt` (Exclusions)
```text
blog.example.com
*.staging.example.com
192.168.1.1
```

---

## Running Tests

Execute the automated pytest suite:
```bash
pytest
```

---
