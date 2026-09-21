# Evaluation Metrics

Reference labels = **LLM** report (SAST tools scored against LLM).

### Binary (VULNERABLE = positive)

| Tool | Accuracy | Precision | Recall | F1 |
|------|----------|-----------|--------|-----|
| cppcheck | 0.577 | 0.400 | 0.444 | 0.421 |
| **flawfinder** | **0.718** | **0.571** | **0.741** | **0.645** |
| rats | 0.641 | 0.490 | 0.889 | 0.632 |
| sast_any | 0.577 | 0.444 | 0.889 | 0.593 |

### Multiclass (exact CWE)

| Tool | Accuracy | Micro-F1 | Macro-F1 | Weighted-F1 |
|------|----------|----------|----------|-------------|
| cppcheck | 0.436 | 0.436 | 0.059 | 0.446 |
| flawfinder | 0.538 | 0.538 | 0.138 | 0.571 |
| **rats** | **0.654** | **0.654** | **0.072** | **0.517** |
| sast_any | 0.449 | 0.449 | 0.102 | 0.506 |

### Project report

- Rows: **218**
- Unique functions: **78**
- Vulnerable-flagged rows: **194** (rate 0.889908)

