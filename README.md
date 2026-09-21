# SAST Analyzer

Workflow:

1. **SAST tools** (cppcheck, flawfinder, RATS) analyze C/C++ code → `sast_report.csv`
2. **LLM** analyzes the same functions → `llm_report.csv` (separate file)
3. **Compare** computes metrics from both reports, then the LLM writes a conclusion

## Tools

| Tool | Source |
|------|--------|
| cppcheck | system install + [cppcheck-opensource/cppcheck](https://github.com/cppcheck-opensource/cppcheck) |
| flawfinder | vendored in `tools/flawfinder` |
| RATS | vendored DB + `tools/rats/rats_scan.py` |

## Setup

```powershell
uv sync
winget install -e --id Cppcheck.Cppcheck   # once per machine
copy .env.example .env                     # fill API key for --llm / compare conclusion
uv run python cli.py check-tools
```

## Usage

```powershell
# SAST only
uv run python cli.py analyze projects/cJSON results/cjson --no-resume

# Full workflow: SAST + LLM + metrics + conclusion
uv run python cli.py analyze projects/cJSON results/cjson --llm --no-resume --max-files 10

# Or compare existing reports later
uv run python cli.py compare results/cjson
```

## Outputs

### Project scan (`cli.py analyze`)

```
results/<run>/
  sast_report.csv
  llm_report.csv          # with --llm
  metrics/
    project_descriptive.json
    binary_metrics_by_tool.csv      # empty until Juliet/benchmark GT exists
    multiclass_metrics_by_tool.csv
    multiclass_per_class_metrics.csv
    sast_vs_llm_agreement.csv       # with --llm
    metrics_full.json
    CONCLUSION.md
```

### Juliet benchmark (`pipeline.py`)

```
results/metrics/
  ALL_binary_evaluation.csv
  ALL_multiclass_evaluation.csv
  binary_metrics_by_tool.csv      # accuracy, precision, recall, F1, ...
  multiclass_metrics_by_tool.csv  # micro/macro/weighted F1
  multiclass_per_class_metrics.csv
  metrics_full.json
  CONCLUSION.md
```
