# Evaluation Metrics

Reference labels = **LLM** report (SAST tools scored against LLM).

### Binary (VULNERABLE = positive)

| Tool | Accuracy | Precision | Recall | F1 |
|------|----------|-----------|--------|-----|
| cppcheck | 0.887 | 0.274 | 0.290 | 0.282 |
| flawfinder | 0.927 | 0.543 | 0.275 | 0.365 |
| rats | 0.922 | 0.485 | 0.232 | 0.314 |
| **sast_any** | **0.882** | **0.320** | **0.478** | **0.384** |

### Multiclass (exact CWE)

| Tool | Accuracy | Micro-F1 | Macro-F1 | Weighted-F1 |
|------|----------|----------|----------|-------------|
| cppcheck | 0.866 | 0.866 | 0.043 | 0.868 |
| flawfinder | 0.908 | 0.908 | 0.056 | 0.889 |
| **rats** | **0.924** | **0.924** | **0.053** | **0.887** |
| sast_any | 0.854 | 0.854 | 0.050 | 0.869 |

### Project report

- Rows: **994**
- Unique functions: **902**
- Vulnerable-flagged rows: **195** (rate 0.196177)

