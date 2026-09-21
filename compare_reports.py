#!/usr/bin/env python3
"""Compare separated SAST vs LLM reports and ask the LLM for a conclusion."""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

load_dotenv()

try:
    from pydantic import Field, create_model
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI

    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False


class Settings:
    OPENAI_API_BASE_URL = os.getenv("OPENAI_API_BASE_URL", "https://api.dslab.tech/v1")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "dummy-key")
    OPENAI_API_MODEL = os.getenv("OPENAI_API_MODEL", "deepseek-v4-flash-0731")


def _truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "y"}


def load_report_rows(csv_path: Path) -> List[Dict[str, Any]]:
    if not csv_path.exists():
        return []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def function_vuln_map(rows: List[Dict[str, Any]]) -> Dict[tuple, Dict[str, Any]]:
    out: Dict[tuple, Dict[str, Any]] = {}
    for row in rows:
        key = (row.get("file_path", ""), row.get("func_name", ""))
        vuln = _truthy(row.get("has_CWE"))
        cwe = (row.get("cwe_id") or "").strip()
        entry = out.setdefault(
            key,
            {"vulnerable": False, "cwes": set(), "messages": [], "analyzers": set()},
        )
        if vuln:
            entry["vulnerable"] = True
        if cwe:
            entry["cwes"].add(cwe)
        msg = (row.get("analyzer_message") or "").strip()
        if msg:
            entry["messages"].append(msg[:200])
        at = (row.get("analyzer_type") or "").strip()
        if at:
            entry["analyzers"].add(at)
    return out


def compute_comparison_metrics(
    sast_rows: List[Dict[str, Any]],
    llm_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    sast_map = function_vuln_map(sast_rows)
    llm_map = function_vuln_map(llm_rows)
    all_keys = set(sast_map) | set(llm_map)

    both_vuln = only_sast = only_llm = both_clean = 0
    cwe_agree = cwe_disagree = 0
    disagreements: List[Dict[str, Any]] = []

    for key in all_keys:
        s = sast_map.get(key, {"vulnerable": False, "cwes": set(), "messages": [], "analyzers": set()})
        l = llm_map.get(key, {"vulnerable": False, "cwes": set(), "messages": [], "analyzers": set()})
        sv, lv = s["vulnerable"], l["vulnerable"]

        if sv and lv:
            both_vuln += 1
            if s["cwes"] and l["cwes"] and (s["cwes"] & l["cwes"]):
                cwe_agree += 1
            elif s["cwes"] or l["cwes"]:
                cwe_disagree += 1
        elif sv and not lv:
            only_sast += 1
            disagreements.append(
                {
                    "file_path": key[0],
                    "func_name": key[1],
                    "sast_vulnerable": True,
                    "llm_vulnerable": False,
                    "sast_cwes": ",".join(sorted(s["cwes"])),
                    "llm_cwes": ",".join(sorted(l["cwes"])),
                    "note": "SAST only",
                }
            )
        elif lv and not sv:
            only_llm += 1
            disagreements.append(
                {
                    "file_path": key[0],
                    "func_name": key[1],
                    "sast_vulnerable": False,
                    "llm_vulnerable": True,
                    "sast_cwes": ",".join(sorted(s["cwes"])),
                    "llm_cwes": ",".join(sorted(l["cwes"])),
                    "note": "LLM only",
                }
            )
        else:
            both_clean += 1

    total = len(all_keys) or 1
    tool_counts: Dict[str, int] = {}
    for row in sast_rows:
        if _truthy(row.get("has_CWE")):
            t = row.get("analyzer_type") or "SAST"
            tool_counts[t] = tool_counts.get(t, 0) + 1

    sast_cwes: Dict[str, int] = {}
    for v in sast_map.values():
        for c in v["cwes"]:
            sast_cwes[c] = sast_cwes.get(c, 0) + 1
    llm_cwes: Dict[str, int] = {}
    for v in llm_map.values():
        for c in v["cwes"]:
            llm_cwes[c] = llm_cwes.get(c, 0) + 1

    return {
        "functions_compared": len(all_keys),
        "sast_total_rows": len(sast_rows),
        "llm_total_rows": len(llm_rows),
        "sast_vulnerable_functions": sum(1 for v in sast_map.values() if v["vulnerable"]),
        "llm_vulnerable_functions": sum(1 for v in llm_map.values() if v["vulnerable"]),
        "agreement_both_vulnerable": both_vuln,
        "agreement_both_clean": both_clean,
        "disagreement_sast_only": only_sast,
        "disagreement_llm_only": only_llm,
        "binary_agreement_rate": round((both_vuln + both_clean) / total, 4),
        "cwe_overlap_on_both_vuln": cwe_agree,
        "cwe_mismatch_on_both_vuln": cwe_disagree,
        "sast_findings_by_tool": tool_counts,
        "sast_cwe_distribution": dict(sorted(sast_cwes.items(), key=lambda x: -x[1])[:20]),
        "llm_cwe_distribution": dict(sorted(llm_cwes.items(), key=lambda x: -x[1])[:20]),
        "disagreement_samples": disagreements[:40],
    }


def write_metrics_csv(metrics: Dict[str, Any], path: Path) -> None:
    rows = [
        ("functions_compared", metrics["functions_compared"]),
        ("sast_total_rows", metrics["sast_total_rows"]),
        ("llm_total_rows", metrics["llm_total_rows"]),
        ("sast_vulnerable_functions", metrics["sast_vulnerable_functions"]),
        ("llm_vulnerable_functions", metrics["llm_vulnerable_functions"]),
        ("agreement_both_vulnerable", metrics["agreement_both_vulnerable"]),
        ("agreement_both_clean", metrics["agreement_both_clean"]),
        ("disagreement_sast_only", metrics["disagreement_sast_only"]),
        ("disagreement_llm_only", metrics["disagreement_llm_only"]),
        ("binary_agreement_rate", metrics["binary_agreement_rate"]),
        ("cwe_overlap_on_both_vuln", metrics["cwe_overlap_on_both_vuln"]),
        ("cwe_mismatch_on_both_vuln", metrics["cwe_mismatch_on_both_vuln"]),
    ]
    for tool, count in metrics["sast_findings_by_tool"].items():
        rows.append((f"sast_tool_{tool}", count))
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])
        w.writerows(rows)


def write_disagreements_csv(metrics: Dict[str, Any], path: Path) -> None:
    fields = [
        "file_path",
        "func_name",
        "sast_vulnerable",
        "llm_vulnerable",
        "sast_cwes",
        "llm_cwes",
        "note",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in metrics.get("disagreement_samples", []):
            w.writerow(row)


def llm_write_conclusion(metrics: Dict[str, Any]) -> str:
    if not LLM_AVAILABLE:
        return (
            "# Conclusion (offline)\n\n"
            "LLM libraries unavailable. Metrics computed locally.\n\n"
            f"```json\n{json.dumps(metrics, indent=2, default=str)[:4000]}\n```\n"
        )

    ConclusionModel = create_model(
        "ComparisonConclusion",
        executive_summary=(str, Field(description="3-6 sentence overall conclusion")),
        agreement_assessment=(str, Field(description="How well SAST and LLM agree")),
        sast_strengths=(str, Field(description="What SAST caught better")),
        llm_strengths=(str, Field(description="What LLM caught better")),
        key_risks=(str, Field(description="Top security risks implied by the reports")),
        recommendations=(str, Field(description="Concrete next steps")),
    )

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a senior application security analyst. Compare SAST tool "
                "findings vs LLM code analysis metrics. Be concrete, cite the numbers, "
                "and avoid fluff.",
            ),
            (
                "human",
                "Comparison metrics between SAST (cppcheck/flawfinder/RATS) and LLM:\n\n"
                "```json\n{metrics}\n```\n\n"
                "Write a clear security assessment and conclusion.",
            ),
        ]
    )

    llm = ChatOpenAI(
        base_url=Settings.OPENAI_API_BASE_URL,
        api_key=Settings.OPENAI_API_KEY,
        model=Settings.OPENAI_API_MODEL,
        temperature=0.2,
    )

    try:
        chain = prompt | llm.with_structured_output(ConclusionModel)
        payload = {k: v for k, v in metrics.items() if k != "disagreement_samples"}
        payload["disagreement_samples"] = metrics.get("disagreement_samples", [])[:25]
        result = chain.invoke({"metrics": json.dumps(payload, indent=2, default=str)})
        return (
            "# SAST vs LLM Comparison Conclusion\n\n"
            f"## Executive summary\n{result.executive_summary}\n\n"
            f"## Agreement assessment\n{result.agreement_assessment}\n\n"
            f"## SAST strengths\n{result.sast_strengths}\n\n"
            f"## LLM strengths\n{result.llm_strengths}\n\n"
            f"## Key risks\n{result.key_risks}\n\n"
            f"## Recommendations\n{result.recommendations}\n"
        )
    except Exception as e:
        return (
            "# Conclusion (LLM error)\n\n"
            f"Failed to generate LLM conclusion: `{e}`\n\n"
            f"```json\n{json.dumps(metrics, indent=2, default=str)[:5000]}\n```\n"
        )


def run_compare_reports(output_dir: Path) -> Dict[str, Any]:
    sast_path = output_dir / "sast_report.csv"
    llm_path = output_dir / "llm_report.csv"
    if not sast_path.exists():
        raise FileNotFoundError(f"Missing SAST report: {sast_path}")
    if not llm_path.exists():
        raise FileNotFoundError(f"Missing LLM report: {llm_path}")

    metrics = compute_comparison_metrics(load_report_rows(sast_path), load_report_rows(llm_path))

    metrics_json = output_dir / "comparison_metrics.json"
    metrics_csv = output_dir / "comparison_metrics.csv"
    disagree_csv = output_dir / "comparison_disagreements.csv"
    conclusion_md = output_dir / "comparison_conclusion.md"

    with open(metrics_json, "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2, default=str)
    write_metrics_csv(metrics, metrics_csv)
    write_disagreements_csv(metrics, disagree_csv)
    conclusion_md.write_text(llm_write_conclusion(metrics), encoding="utf-8")

    return {
        "metrics": metrics,
        "metrics_json": metrics_json,
        "metrics_csv": metrics_csv,
        "disagree_csv": disagree_csv,
        "conclusion_md": conclusion_md,
    }
