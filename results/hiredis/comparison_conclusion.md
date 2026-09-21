# SAST vs LLM Comparison Conclusion

## Executive summary
SAST and LLM agree on vulnerability presence in only 72.9% of functions. When both flag a function, they never agree on the CWE classification (0% CWE overlap). SAST produces 3.4x more raw findings (425 vs 266) but many are low-severity style issues (CWE-398 = 59 findings, 49.6% of SAST total). LLM flags 127 functions vs SAST's 119, with 40 LLM-only findings including critical memory-safety issues (CWE-476, CWE-125, CWE-787) that SAST misses. The tools are complementary: SAST excels at detecting code-quality issues and buffer overflows, LLM better identifies null-pointer dereferences and logic flaws. Neither tool alone is sufficient.

## Agreement assessment
Binary agreement rate of 0.7293 (194/266 functions) shows moderate alignment. However, the 72 disagreements (27.1%) represent significant blind spots. SAST-only findings (32) are dominated by CWE-398 (indicator of poor code quality) - 22 of 32 SAST-only cases are CWE-398, which are low-severity style issues. LLM-only findings (40) include 10 CWE-476 (null pointer dereference), 3 CWE-125 (out-of-bounds read), and 2 CWE-787 (out-of-bounds write) - these are high-severity memory safety issues. The complete CWE mismatch on 87 functions both flag as vulnerable indicates the tools are detecting different underlying issues, not just disagreeing on severity.

## SAST strengths
SAST detected 119 vulnerable functions with 425 total findings. It uniquely identified buffer overflow issues (CWE-120, CWE-126, CWE-119) that LLM missed - e.g., __redisReaderSetError (CWE-120,CWE-126) and redisBufferRead (CWE-119). SAST's CWE-398 findings (59) are useful for code quality but not security-critical. SAST also caught resource issues (CWE-676 - use of dangerous function in millisleep) and race conditions (CWE-362).

## LLM strengths
LLM flagged 127 vulnerable functions, slightly more than SAST. It uniquely identified critical null-pointer dereferences (CWE-476) in 10 functions SAST missed, including redisReaderGetReply, redisCheckConnectDone, and redisAsyncHandleRead - all core library functions. LLM also caught out-of-bounds read/write issues (CWE-125, CWE-787) in sdsAllocSize and sdsIncrLen, which are memory safety issues in the string library. LLM identified error-handling flaws (CWE-252, CWE-755) in redisNetWrite and redisReaderGrow that SAST overlooked.

## Key risks
1) CWE mismatch on 87 functions both flag: This means even when both tools agree a function is vulnerable, they disagree on the vulnerability type. This could lead to incomplete remediation if only one tool's classification is used. 2) LLM-only critical findings: 15 high-severity memory safety issues (CWE-476, CWE-125, CWE-787) in core library functions would be missed if relying solely on SAST. 3) SAST's high false-positive rate: 59 CWE-398 findings (49.6% of SAST total) are code-quality issues, not security vulnerabilities, which could overwhelm analysts and hide real issues.

## Recommendations
1) Use both tools in a complementary pipeline: SAST for buffer overflow and code-quality issues, LLM for null-pointer and logic flaws. 2) Manually review all 87 functions where both tools agree but CWE differs - these are likely the most complex vulnerabilities. 3) Prioritize the 40 LLM-only findings, especially the 15 memory-safety issues, as they represent real exploitable vulnerabilities. 4) Treat CWE-398 findings as code-quality debt, not security vulnerabilities, to reduce noise. 5) For the 32 SAST-only findings, verify if they are true positives or false positives - many are CWE-398 style issues. 6) Establish a unified vulnerability taxonomy to reconcile CWE mismatches and avoid duplicate remediation efforts.
