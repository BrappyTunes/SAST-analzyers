# SAST Analyzer

Scan C/C++ projects (local folders or GitHub repos) with three SAST tools and write a **CSV** report.

## Tools (from GitHub)

| Tool | Source | Role |
|------|--------|------|
| **cppcheck** | [cppcheck-opensource/cppcheck](https://github.com/cppcheck-opensource/cppcheck) | Deep C/C++ static analysis |
| **flawfinder** | [david-a-wheeler/flawfinder](https://github.com/david-a-wheeler/flawfinder) | Dangerous-function / CWE scanner |
| **RATS** | [andrew-d/rough-auditing-tool-for-security](https://github.com/andrew-d/rough-auditing-tool-for-security) | Rough auditing (Windows uses `rats_scan.py` + official vuln DB) |

Cloned under `tools/`. System cppcheck is installed via winget.

## Setup

```powershell
uv sync
uv run python cli.py check-tools
```

Optional LLM (`.env`):

```
OPENAI_API_BASE_URL=https://api.dslab.tech/v1
OPENAI_API_KEY=your-key
OPENAI_API_MODEL=deepseek-v4-flash-0731
```

## Usage

```powershell
# Local folder
uv run python cli.py analyze ./projects/cJSON results/cjson --no-resume

# GitHub owner/repo (clones into projects/)
uv run python cli.py analyze DaveGamble/cJSON results/cjson --max-files 30

# Full GitHub URL + optional LLM
uv run python cli.py analyze https://github.com/DaveGamble/cJSON results/cjson --llm

# Juliet evaluation pipeline (CSV accuracy tables)
uv run python pipeline.py analyze ./juliet --sample 50
```

## Output

In the output directory:

- `analysis_report.csv` — main table
- `analysis_results.jsonl`
- `analysis_report.xlsx`
