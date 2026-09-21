#!/usr/bin/env python3
"""Benchmark evaluation metrics for binary / multiclass SAST+LLM reports."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd


POSITIVE_BINARY = "VULNERABLE"
NEGATIVE_BINARY = "NON_VULNERABLE"


def _safe_div(n: float, d: float) -> float:
    return float(n) / float(d) if d else 0.0


def binary_metrics_from_labels(y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
    """Binary metrics treating VULNERABLE as the positive class."""
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        t_pos = str(t).strip().upper() == POSITIVE_BINARY
        p_pos = str(p).strip().upper() == POSITIVE_BINARY
        if t_pos and p_pos:
            tp += 1
        elif not t_pos and p_pos:
            fp += 1
        elif not t_pos and not p_pos:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, total)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)

    return {
        "n": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "specificity": round(specificity, 6),
        "f1": round(f1, 6),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(fnr, 6),
        "positive_support_gt": tp + fn,
        "negative_support_gt": tn + fp,
    }


def multiclass_metrics_from_labels(y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
    """Accuracy + micro/macro/weighted precision/recall/F1 over CWE labels."""
    labels = sorted({str(x).strip() for x in y_true} | {str(x).strip() for x in y_pred})
    # confusion counts per class
    tp = {c: 0 for c in labels}
    fp = {c: 0 for c in labels}
    fn = {c: 0 for c in labels}
    support = {c: 0 for c in labels}

    correct = 0
    n = len(y_true)
    for t, p in zip(y_true, y_pred):
        t, p = str(t).strip(), str(p).strip()
        support[t] = support.get(t, 0) + 1
        if t == p:
            correct += 1
            tp[t] = tp.get(t, 0) + 1
        else:
            fn[t] = fn.get(t, 0) + 1
            fp[p] = fp.get(p, 0) + 1

    per_class: Dict[str, Dict[str, float]] = {}
    precisions, recalls, f1s, weights = [], [], [], []
    for c in labels:
        p = _safe_div(tp[c], tp[c] + fp[c])
        r = _safe_div(tp[c], tp[c] + fn[c])
        f1 = _safe_div(2 * p * r, p + r)
        per_class[c] = {
            "precision": round(p, 6),
            "recall": round(r, 6),
            "f1": round(f1, 6),
            "support": support.get(c, 0),
        }
        precisions.append(p)
        recalls.append(r)
        f1s.append(f1)
        weights.append(support.get(c, 0))

    # micro: aggregate TP/FP/FN (for multiclass single-label, micro-P=R=Acc)
    sum_tp = sum(tp.values())
    sum_fp = sum(fp.values())
    sum_fn = sum(fn.values())
    micro_p = _safe_div(sum_tp, sum_tp + sum_fp)
    micro_r = _safe_div(sum_tp, sum_tp + sum_fn)
    micro_f1 = _safe_div(2 * micro_p * micro_r, micro_p + micro_r)

    k = len(labels) or 1
    macro_p = sum(precisions) / k
    macro_r = sum(recalls) / k
    macro_f1 = sum(f1s) / k

    wsum = sum(weights) or 1
    weighted_p = sum(p * w for p, w in zip(precisions, weights)) / wsum
    weighted_r = sum(r * w for r, w in zip(recalls, weights)) / wsum
    weighted_f1 = sum(f * w for f, w in zip(f1s, weights)) / wsum

    return {
        "n": n,
        "n_classes": len(labels),
        "accuracy": round(_safe_div(correct, n), 6),
        "micro_precision": round(micro_p, 6),
        "micro_recall": round(micro_r, 6),
        "micro_f1": round(micro_f1, 6),
        "macro_precision": round(macro_p, 6),
        "macro_recall": round(macro_r, 6),
        "macro_f1": round(macro_f1, 6),
        "weighted_precision": round(weighted_p, 6),
        "weighted_recall": round(weighted_r, 6),
        "weighted_f1": round(weighted_f1, 6),
        "per_class": per_class,
    }


def evaluate_binary_csv(path: Path, tool_col: str = "tool") -> Dict[str, Any]:
    df = pd.read_csv(path)
    required = {"gt_binary", "pred_binary", tool_col}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} missing columns: {missing}")

    out: Dict[str, Any] = {"source": str(path), "by_tool": {}}
    for tool, g in df.groupby(tool_col):
        out["by_tool"][str(tool)] = binary_metrics_from_labels(
            g["gt_binary"].astype(str).tolist(),
            g["pred_binary"].astype(str).tolist(),
        )
    # overall across all tools (pooled)
    out["pooled_all_tools"] = binary_metrics_from_labels(
        df["gt_binary"].astype(str).tolist(),
        df["pred_binary"].astype(str).tolist(),
    )
    return out


def evaluate_multiclass_csv(path: Path, tool_col: str = "tool") -> Dict[str, Any]:
    df = pd.read_csv(path)
    required = {"gt_multiclass", "pred_multiclass", tool_col}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} missing columns: {missing}")

    out: Dict[str, Any] = {"source": str(path), "by_tool": {}}
    for tool, g in df.groupby(tool_col):
        out["by_tool"][str(tool)] = multiclass_metrics_from_labels(
            g["gt_multiclass"].astype(str).tolist(),
            g["pred_multiclass"].astype(str).tolist(),
        )
    out["pooled_all_tools"] = multiclass_metrics_from_labels(
        df["gt_multiclass"].astype(str).tolist(),
        df["pred_multiclass"].astype(str).tolist(),
    )
    return out


def summarize_ungrounded_report(path: Path) -> Dict[str, Any]:
    """Descriptive stats for reports without ground truth (e.g. cJSON)."""
    if path.suffix.lower() in {".xlsx", ".xls"}:
        df = pd.read_excel(path)
    else:
        df = pd.read_csv(path)

    cols = set(df.columns)
    summary: Dict[str, Any] = {
        "source": str(path),
        "has_ground_truth": False,
        "note": "No ground-truth labels — accuracy/recall cannot be computed.",
        "n_rows": int(len(df)),
    }

    if "has_CWE" in cols:
        vuln = df["has_CWE"].astype(str).str.lower().isin(["true", "1", "yes"])
        summary["vulnerable_rows"] = int(vuln.sum())
        summary["clean_rows"] = int((~vuln).sum())
        summary["vulnerable_rate"] = round(_safe_div(vuln.sum(), len(df)), 6)

    if "analyzer_type" in cols:
        summary["findings_by_analyzer"] = (
            df.loc[df.get("has_CWE", False) == True, "analyzer_type"]  # noqa: E712
            .fillna("None")
            .value_counts()
            .to_dict()
            if "has_CWE" in cols
            else df["analyzer_type"].fillna("None").value_counts().to_dict()
        )

    if "cwe_id" in cols:
        cwes = df["cwe_id"].dropna().astype(str)
        cwes = cwes[cwes.str.len() > 0]
        summary["top_cwes"] = cwes.value_counts().head(20).to_dict()

    if {"file_path", "func_name"}.issubset(cols):
        summary["unique_functions"] = int(df.groupby(["file_path", "func_name"]).ngroups)
    elif {"file", "func"}.issubset(cols):
        summary["unique_functions"] = int(df.groupby(["file", "func"]).ngroups)

    return summary


def metrics_tables(binary: Dict[str, Any], multiclass: Dict[str, Any]) -> tuple[pd.DataFrame, pd.DataFrame]:
    bin_rows = []
    for tool, m in binary.get("by_tool", {}).items():
        bin_rows.append({"tool": tool, **{k: v for k, v in m.items()}})
    multi_rows = []
    for tool, m in multiclass.get("by_tool", {}).items():
        row = {"tool": tool}
        for k, v in m.items():
            if k != "per_class":
                row[k] = v
        multi_rows.append(row)
    return pd.DataFrame(bin_rows), pd.DataFrame(multi_rows)


def write_conclusion_md(
    binary: Dict[str, Any],
    multiclass: Dict[str, Any],
    cjson: Optional[Dict[str, Any]],
    path: Path,
) -> None:
    lines = [
        "# Evaluation Metrics Conclusion",
        "",
        "## Scope",
        "",
        "- **Binary / multiclass CSVs**: Juliet-style benchmark with ground truth -> full metrics.",
        "- **cJSON report**: real project scan without ground truth -> descriptive stats only.",
        "",
        "## Binary (VULNERABLE vs NON_VULNERABLE)",
        "",
        "| Tool | Accuracy | Precision | Recall | F1 | Specificity | FPR | FNR | N |",
        "|------|----------|-----------|--------|----|-------------|-----|-----|---|",
    ]
    for tool, m in binary.get("by_tool", {}).items():
        lines.append(
            f"| {tool} | {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | "
            f"{m['f1']:.4f} | {m['specificity']:.4f} | {m['false_positive_rate']:.4f} | "
            f"{m['false_negative_rate']:.4f} | {m['n']} |"
        )

    # Best tools
    if binary.get("by_tool"):
        best_f1 = max(binary["by_tool"].items(), key=lambda x: x[1]["f1"])
        best_rec = max(binary["by_tool"].items(), key=lambda x: x[1]["recall"])
        best_acc = max(binary["by_tool"].items(), key=lambda x: x[1]["accuracy"])
        lines += [
            "",
            "### Binary takeaways",
            "",
            f"- Best **F1**: **{best_f1[0]}** ({best_f1[1]['f1']:.4f})",
            f"- Best **Recall** (fewer missed vulns): **{best_rec[0]}** ({best_rec[1]['recall']:.4f})",
            f"- Best **Accuracy**: **{best_acc[0]}** ({best_acc[1]['accuracy']:.4f})",
            "- High specificity with low recall usually means the tool is conservative (many misses).",
            "- High recall with low precision usually means noisy alerts (many false positives).",
            "",
        ]

    lines += [
        "## Multiclass (exact CWE)",
        "",
        "| Tool | Accuracy | Micro-P | Micro-R | Micro-F1 | Macro-P | Macro-R | Macro-F1 | Weighted-F1 | Classes | N |",
        "|------|----------|---------|---------|----------|---------|---------|----------|-------------|---------|---|",
    ]
    for tool, m in multiclass.get("by_tool", {}).items():
        lines.append(
            f"| {tool} | {m['accuracy']:.4f} | {m['micro_precision']:.4f} | {m['micro_recall']:.4f} | "
            f"{m['micro_f1']:.4f} | {m['macro_precision']:.4f} | {m['macro_recall']:.4f} | "
            f"{m['macro_f1']:.4f} | {m['weighted_f1']:.4f} | {m['n_classes']} | {m['n']} |"
        )

    if multiclass.get("by_tool"):
        best_micro = max(multiclass["by_tool"].items(), key=lambda x: x[1]["micro_f1"])
        best_macro = max(multiclass["by_tool"].items(), key=lambda x: x[1]["macro_f1"])
        lines += [
            "",
            "### Multiclass takeaways",
            "",
            f"- Best **micro-F1** (overall exact-CWE): **{best_micro[0]}** ({best_micro[1]['micro_f1']:.4f})",
            f"- Best **macro-F1** (balanced across CWEs): **{best_macro[0]}** ({best_macro[1]['macro_f1']:.4f})",
            "- Macro scores punish tools that only work on a few frequent CWEs.",
            "- Micro equals accuracy here for single-label exact match.",
            "",
        ]

    lines += ["## Project report (no ground truth)", ""]
    if cjson:
        lines += [
            f"- Rows: **{cjson.get('n_rows')}**",
            f"- Unique functions: **{cjson.get('unique_functions', 'n/a')}**",
            f"- Vulnerable-flagged rows: **{cjson.get('vulnerable_rows', 'n/a')}** "
            f"(rate {cjson.get('vulnerable_rate', 'n/a')})",
            f"- By analyzer: `{cjson.get('findings_by_analyzer', {})}`",
            f"- Top CWEs: `{cjson.get('top_cwes', {})}`",
            "",
            "**Note:** This project scan has **no ground truth**, so accuracy/recall/F1 "
            "are not defined. Run `pipeline.py` on Juliet (or labeled data) for those metrics.",
            "",
        ]
    else:
        lines.append("No ungrounded project report provided.\n")

    lines += [
        "## Overall conclusion",
        "",
        "1. Use **binary recall + F1** to judge vulnerability detection usefulness.",
        "2. Use **multiclass macro-F1** to judge whether CWE identification generalizes.",
        "3. Prefer tools (or ensembles) that keep recall high without collapsing precision.",
        "4. Real projects need labeled ground truth before claiming accuracy.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def export_evaluation(
    binary_csv: Path,
    multiclass_csv: Path,
    out_dir: Path,
    ungrounded_report: Optional[Path] = None,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = evaluate_binary_csv(binary_csv)
    multiclass = evaluate_multiclass_csv(multiclass_csv)
    project = summarize_ungrounded_report(ungrounded_report) if ungrounded_report else None

    bin_df, multi_df = metrics_tables(binary, multiclass)
    bin_path = out_dir / "binary_metrics_by_tool.csv"
    multi_path = out_dir / "multiclass_metrics_by_tool.csv"
    bin_df.to_csv(bin_path, index=False)
    multi_df.to_csv(multi_path, index=False)

    per_class_rows = []
    for tool, m in multiclass["by_tool"].items():
        for label, stats in m.get("per_class", {}).items():
            per_class_rows.append({"tool": tool, "label": label, **stats})
    per_class_df = pd.DataFrame(per_class_rows)
    per_class_path = out_dir / "multiclass_per_class_metrics.csv"
    per_class_df.to_csv(per_class_path, index=False)

    payload = {"binary": binary, "multiclass": multiclass, "project_descriptive": project}
    json_path = out_dir / "metrics_full.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)

    conclusion_path = out_dir / "CONCLUSION.md"
    write_conclusion_md(binary, multiclass, project, conclusion_path)

    if project:
        with open(out_dir / "project_descriptive.json", "w", encoding="utf-8") as f:
            json.dump(project, f, ensure_ascii=False, indent=2)

    # Keep a copy of source evaluation tables inside metrics/
    try:
        import shutil

        shutil.copy2(binary_csv, out_dir / "ALL_binary_evaluation.csv")
        shutil.copy2(multiclass_csv, out_dir / "ALL_multiclass_evaluation.csv")
    except OSError:
        pass

    return {
        "out_dir": out_dir,
        "binary_csv": bin_path,
        "multiclass_csv": multi_path,
        "per_class_csv": per_class_path,
        "json": json_path,
        "conclusion": conclusion_path,
        "binary": binary,
        "multiclass": multiclass,
        "project": project,
        "cjson": project,  # backward-compatible alias
    }


def export_ungrounded_metrics(report_path: Path, out_dir: Path) -> Dict[str, Any]:
    """Write the same metrics/ layout for scans without ground truth."""
    out_dir.mkdir(parents=True, exist_ok=True)
    project = summarize_ungrounded_report(report_path)

    empty_binary = pd.DataFrame(
        columns=[
            "tool",
            "n",
            "tp",
            "fp",
            "tn",
            "fn",
            "accuracy",
            "precision",
            "recall",
            "specificity",
            "f1",
            "false_positive_rate",
            "false_negative_rate",
            "positive_support_gt",
            "negative_support_gt",
        ]
    )
    empty_multi = pd.DataFrame(
        columns=[
            "tool",
            "n",
            "n_classes",
            "accuracy",
            "micro_precision",
            "micro_recall",
            "micro_f1",
            "macro_precision",
            "macro_recall",
            "macro_f1",
            "weighted_precision",
            "weighted_recall",
            "weighted_f1",
        ]
    )
    empty_binary.to_csv(out_dir / "binary_metrics_by_tool.csv", index=False)
    empty_multi.to_csv(out_dir / "multiclass_metrics_by_tool.csv", index=False)
    pd.DataFrame(columns=["tool", "label", "precision", "recall", "f1", "support"]).to_csv(
        out_dir / "multiclass_per_class_metrics.csv", index=False
    )

    with open(out_dir / "project_descriptive.json", "w", encoding="utf-8") as f:
        json.dump(project, f, ensure_ascii=False, indent=2)

    payload = {
        "binary": None,
        "multiclass": None,
        "project_descriptive": project,
        "note": "No ground truth — accuracy/recall/F1 not computed. Use Juliet pipeline for benchmark metrics.",
    }
    json_path = out_dir / "metrics_full.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    conclusion_path = out_dir / "CONCLUSION.md"
    write_conclusion_md({"by_tool": {}}, {"by_tool": {}}, project, conclusion_path)
    return {
        "out_dir": out_dir,
        "json": json_path,
        "conclusion": conclusion_path,
        "project": project,
    }


def write_run_metrics_package(run_dir: Path) -> Dict[str, Any]:
    """
    Auto-export a metrics/ folder for a run directory.

    Prefer benchmark ALL_* CSVs if present; otherwise descriptive metrics from sast/llm reports.
    """
    metrics_dir = run_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)

    # Search common locations for benchmark eval tables
    candidates = [
        (run_dir / "ALL_binary_evaluation.csv", run_dir / "ALL_multiclass_evaluation.csv"),
        (run_dir / "binary" / "ALL_binary_evaluation.csv", run_dir / "multiclass" / "ALL_multiclass_evaluation.csv"),
        (run_dir.parent / "binary" / "ALL_binary_evaluation.csv", run_dir.parent / "multiclass" / "ALL_multiclass_evaluation.csv"),
    ]
    for bin_p, multi_p in candidates:
        if bin_p.exists() and multi_p.exists():
            ungrounded = None
            for name in ("sast_report.csv", "llm_report.csv", "analysis_report.csv"):
                p = run_dir / name
                if p.exists():
                    ungrounded = p
                    break
            return export_evaluation(bin_p, multi_p, metrics_dir, ungrounded_report=ungrounded)

    # Project scan path (no GT)
    report = None
    for name in ("sast_report.csv", "llm_report.csv", "analysis_report.csv"):
        p = run_dir / name
        if p.exists():
            report = p
            break
    if report is None:
        raise FileNotFoundError(f"No reports found under {run_dir}")

    result = export_ungrounded_metrics(report, metrics_dir)

    # If both SAST and LLM exist, also store agreement tables inside metrics/
    sast_p = run_dir / "sast_report.csv"
    llm_p = run_dir / "llm_report.csv"
    if sast_p.exists() and llm_p.exists():
        try:
            from compare_reports import (
                compute_comparison_metrics,
                load_report_rows,
                write_disagreements_csv,
                write_metrics_csv,
            )

            cmp = compute_comparison_metrics(load_report_rows(sast_p), load_report_rows(llm_p))
            write_metrics_csv(cmp, metrics_dir / "sast_vs_llm_agreement.csv")
            write_disagreements_csv(cmp, metrics_dir / "sast_vs_llm_disagreements.csv")
            with open(metrics_dir / "sast_vs_llm_agreement.json", "w", encoding="utf-8") as f:
                json.dump(cmp, f, ensure_ascii=False, indent=2, default=str)
            result["agreement"] = cmp
        except Exception:
            pass

    return result
