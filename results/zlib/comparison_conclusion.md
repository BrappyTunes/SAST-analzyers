# SAST vs LLM Comparison Conclusion

## Executive summary
SAST tools flagged 54 of 78 functions (69.2%) as vulnerable, while LLM flagged only 27 (34.6%). Binary agreement is 57.7% (45/78). SAST has 30 false positives relative to LLM, LLM has 3 false positives relative to SAST. CWE overlap on jointly flagged functions is only 7 of 24 (29.2%), indicating poor taxonomic alignment. SAST over-reports low-severity issues (CWE-398, CWE-119) while LLM under-reports but shows higher precision on memory-safety CWEs.

## Agreement assessment
The tools agree on 24 vulnerable and 21 clean functions (45/78 = 57.7%). This is barely better than chance (50%). The 30 SAST-only findings are dominated by CWE-398 (code quality), CWE-119 (buffer errors), and CWE-120 (buffer copy). Many SAST-only findings are in utility functions (do_banner, do_help, myGetRDTSC32) that are not security-critical. The 3 LLM-only findings (CWE-476, CWE-131) are memory-safety issues that SAST missed, suggesting LLM can catch subtle allocation/dereference bugs.

## SAST strengths
SAST detected 24 true positives (agreed by LLM) and 30 additional findings. It covers a broad CWE range (14 distinct CWEs) and flags many functions. SAST is strong at detecting buffer overflows (CWE-119: 22 findings) and code quality issues (CWE-398: 19 findings). It also catches race conditions (CWE-362) and dead code (CWE-563) that LLM may ignore.

## LLM strengths
LLM has a much lower false positive rate (3 vs 30). Its 27 findings are more concentrated on memory-safety (CWE-120, CWE-787, CWE-190, CWE-476, CWE-125, CWE-416). LLM uniquely identified CWE-787 (out-of-bounds write) and CWE-416 (use-after-free) which SAST missed entirely. LLM's precision is higher: 24/27 (88.9%) of its findings are confirmed by SAST, versus SAST's 24/54 (44.4%) confirmed by LLM.

## Key risks
1) SAST's 30 unconfirmed findings may overwhelm developers with false positives, especially CWE-398 (code style) and CWE-119 (generic buffer). 2) LLM's 3 missed findings (CWE-476, CWE-131) are real memory bugs that SAST caught, so LLM alone is insufficient. 3) CWE mismatch on 17 of 24 jointly flagged functions means even when both agree a function is vulnerable, they disagree on the vulnerability type—this complicates remediation prioritization.

## Recommendations
1) Use SAST as a broad filter, then use LLM to triage and prioritize—focus on functions where both agree (24) and on LLM-only findings (3) as high-confidence. 2) Suppress SAST findings with CWE-398 (code quality) unless they co-occur with memory-safety CWEs. 3) Manually review the 17 CWE mismatches to resolve true vulnerability type. 4) For production, combine both: SAST for coverage, LLM for precision. 5) The 3 LLM-only findings (CWE-476, CWE-131) should be verified immediately as they are memory-safety issues missed by SAST.
