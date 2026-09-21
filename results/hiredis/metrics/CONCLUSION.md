# Evaluation Metrics

Reference labels = **LLM** report (SAST tools scored against LLM).

### Binary (VULNERABLE = positive)

| Tool | Accuracy | Precision | Recall | F1 |
|------|----------|-----------|--------|-----|
| cppcheck | 0.643 | 0.742 | 0.386 | 0.508 |
| flawfinder | 0.602 | 0.756 | 0.244 | 0.369 |
| rats | 0.707 | 0.753 | 0.575 | 0.652 |
| **sast_any** | **0.729** | **0.731** | **0.685** | **0.707** |

### Multiclass (exact CWE)

| Tool | Accuracy | Micro-F1 | Macro-F1 | Weighted-F1 |
|------|----------|----------|----------|-------------|
| cppcheck | 0.462 | 0.462 | 0.023 | 0.377 |
| flawfinder | 0.485 | 0.485 | 0.024 | 0.370 |
| **rats** | **0.523** | **0.523** | **0.025** | **0.359** |
| sast_any | 0.440 | 0.440 | 0.023 | 0.377 |

### Project report

- Rows: **425**
- Unique functions: **266**
- Vulnerable-flagged rows: **278** (rate 0.654118)

