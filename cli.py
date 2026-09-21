#!/usr/bin/env python3
"""SAST analyzer CLI: scan local dirs or GitHub repos with cppcheck, flawfinder, RATS."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import typer
from dotenv import load_dotenv

load_dotenv()

try:
    from tools_paths import scanners_config
except ImportError:
    scanners_config = None  # type: ignore

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


app = typer.Typer(help="C/C++ SAST pipeline (cppcheck + flawfinder + RATS)", add_completion=False)

LLM_CACHE_FILE = ".llm_cache.json"
BATCH_SIZE = 50
CHECKPOINT_FILE = ".analysis_checkpoint.json"
PROJECTS_DIR = Path("projects")

COLUMNS = [
    "file_path",
    "func_name",
    "has_CWE",
    "cwe_id",
    "analyzer_message",
    "analyzer_type",
    "line_range",
]


def load_llm_cache() -> dict:
    if os.path.exists(LLM_CACHE_FILE):
        try:
            with open(LLM_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_llm_cache(cache: dict) -> None:
    with open(LLM_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def load_checkpoint(path: Path) -> dict:
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_checkpoint(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def extract_cwe_id(text: str) -> Optional[str]:
    if not text:
        return None
    match = re.search(r"CWE[-_]?\s*(\d{1,4})", text, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    return None


class BatchWriter:
    """Writes results in batches to CSV, JSONL, and Excel."""

    def __init__(self, output_dir: Path, prefix: str, batch_size: int = BATCH_SIZE):
        self.output_dir = output_dir
        self.prefix = prefix
        self.batch_size = batch_size
        self.buffer: List[Dict[str, Any]] = []
        self.total_written = 0

        self.csv_path = output_dir / f"{prefix}.csv"
        self.jsonl_path = output_dir / f"{prefix}.jsonl"
        self.xlsx_path = output_dir / f"{prefix}.xlsx"

        self._jsonl_file = open(self.jsonl_path, "a", encoding="utf-8")

        write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
        self._csv_file = open(self.csv_path, "a", encoding="utf-8", newline="")
        self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=COLUMNS, extrasaction="ignore")
        if write_header:
            self._csv_writer.writeheader()

        self._wb = None
        self._ws = None
        try:
            from openpyxl import Workbook, load_workbook

            if self.xlsx_path.exists():
                self._wb = load_workbook(str(self.xlsx_path))
                self._ws = self._wb.active
            else:
                self._wb = Workbook()
                self._ws = self._wb.active
                self._ws.title = prefix[:31]
                self._ws.append(COLUMNS)
                self._ws.freeze_panes = "A2"
        except Exception:
            self._wb = None
            self._ws = None

    def append(self, row: Dict[str, Any]) -> None:
        self.buffer.append(row)
        if len(self.buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return

        for row in self.buffer:
            self._jsonl_file.write(json.dumps(row, ensure_ascii=False) + "\n")
            self._csv_writer.writerow({c: row.get(c, "") for c in COLUMNS})
        self._jsonl_file.flush()
        self._csv_file.flush()

        if self._ws is not None and self._wb is not None:
            for row in self.buffer:
                self._ws.append([row.get(c, "") for c in COLUMNS])
            self._wb.save(str(self.xlsx_path))

        self.total_written += len(self.buffer)
        typer.echo(f"  [{self.prefix}] flushed {len(self.buffer)} (total: {self.total_written})")
        self.buffer.clear()

    def close(self) -> None:
        self.flush()
        if self._jsonl_file:
            self._jsonl_file.close()
        if self._csv_file:
            self._csv_file.close()
        if self._wb:
            self._wb.save(str(self.xlsx_path))

def extract_functions(filepath: str) -> Dict[str, Dict[str, Any]]:
    functions: Dict[str, Dict[str, Any]] = {}
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        current_func = None
        brace_count = 0
        start_line = 0
        func_lines: list[str] = []

        for i, line in enumerate(lines, 1):
            func_match = re.match(
                r"(?:static\s+)?(?:void|int|char|float|double|bool|long|short|unsigned|signed|size_t|ssize_t)\s*\*?\s+(\w+)\s*\([^)]*\)\s*\{?",
                line,
            )

            if func_match and brace_count == 0:
                current_func = func_match.group(1)
                start_line = i
                func_lines = [line]
                brace_count = line.count("{") - line.count("}")
            elif current_func:
                func_lines.append(line)
                brace_count += line.count("{") - line.count("}")
                if brace_count == 0:
                    functions[current_func] = {
                        "start": start_line,
                        "end": i,
                        "code": "".join(func_lines),
                    }
                    current_func = None
                    func_lines = []
    except Exception as e:
        typer.echo(f"Warning: failed to read {filepath}: {e}")
    return functions


def get_scanners() -> dict:
    if scanners_config is not None:
        return scanners_config()
    return {
        "cppcheck": {
            "cmd": [
                "cppcheck",
                "--enable=warning,performance,portability,style",
                "--xml",
                "--xml-version=2",
                "{target}",
            ],
            "stderr": True,
        },
        "flawfinder": {
            "cmd": ["flawfinder", "--csv", "--quiet", "{target}"],
            "stderr": False,
        },
        "rats": {
            "cmd": ["rats", "--xml", "{target}"],
            "stderr": False,
        },
    }


def run_sast_on_file(filepath: str) -> Dict[int, List[Dict[str, str]]]:
    results: Dict[int, List[Dict[str, str]]] = {}
    filename = os.path.basename(filepath)

    for name, cfg in get_scanners().items():
        cmd = [filepath if p == "{target}" else p for p in cfg["cmd"]]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
            output = r.stderr if cfg.get("stderr") else r.stdout

            if name == "cppcheck":
                try:
                    # cppcheck wraps output; find XML root
                    xml_start = output.find("<?xml")
                    if xml_start < 0:
                        xml_start = output.find("<results")
                    xml_text = output[xml_start:] if xml_start >= 0 else output
                    for err in ET.fromstring(xml_text).findall(".//error"):
                        msg = err.get("msg") or err.get("verbose", "Unknown cppcheck issue")
                        cwe_id = err.get("cwe")
                        if cwe_id:
                            cwe_id = f"CWE-{cwe_id}"
                        for loc in err.findall("location"):
                            if os.path.basename(loc.get("file", "")) == filename:
                                line = int(loc.get("line", 0))
                                if line > 0:
                                    results.setdefault(line, []).append(
                                        {
                                            "analyzer": name,
                                            "message": msg,
                                            "cwe_id": cwe_id or extract_cwe_id(msg) or "",
                                        }
                                    )
                except ET.ParseError:
                    pass

            elif name == "flawfinder":
                lines = [ln for ln in output.splitlines() if ln.strip()]
                if not lines:
                    continue
                reader = csv.DictReader(lines)
                for row in reader:
                    if os.path.basename(row.get("File", "") or row.get("filename", "")) == filename:
                        line = int(row.get("Line", 0) or row.get("line", 0) or 0)
                        warning = row.get("Warning") or ""
                        note = row.get("Note") or ""
                        context = row.get("Context") or ""
                        msg = warning or note or context or row.get("Message") or "Unknown flawfinder issue"
                        cwe = row.get("CWEs") or row.get("CWE") or ""
                        if line > 0:
                            results.setdefault(line, []).append(
                                {
                                    "analyzer": name,
                                    "message": msg.strip(),
                                    "cwe_id": extract_cwe_id(cwe) or extract_cwe_id(msg) or "",
                                }
                            )

            elif name == "rats":
                try:
                    for vuln in ET.fromstring(output).findall(".//vulnerability"):
                        file_elem = vuln.find("file")
                        line_elem = vuln.find("line")
                        if file_elem is not None and os.path.basename(file_elem.text or "") == filename:
                            if line_elem is not None and line_elem.text:
                                line = int(line_elem.text)
                                name_el = vuln.find("name")
                                msg = name_el.text if name_el is not None else "RATS vulnerability"
                                if line > 0:
                                    results.setdefault(line, []).append(
                                        {
                                            "analyzer": name,
                                            "message": msg,
                                            "cwe_id": extract_cwe_id(msg) or "",
                                        }
                                    )
                except ET.ParseError:
                    pass

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            typer.echo(f"  warning: {name} failed on {filename}: {e}")

    return results


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique_findings = []
    for finding in findings:
        key = (
            finding["file_path"],
            finding["func_name"],
            finding["cwe_id"],
            finding["analyzer_message"],
            finding["analyzer_type"],
        )
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    return unique_findings


CWE_CODES = tuple(f"CWE-{i}" for i in range(100, 1000)) + ("NO_CWE",)


def analyze_function_with_llm(func_code: str, func_name: str) -> Dict[str, Any]:
    if not LLM_AVAILABLE:
        return {"has_cwe": False, "cwe_code": None, "message": "LLM libraries not installed", "success": False}

    from typing import Literal

    CWEType = Literal.__getitem__(CWE_CODES)  # type: ignore[attr-defined]

    AnalysisModel = create_model(
        "FunctionAnalysis",
        has_cwe=(bool, Field(description="True if vulnerability exists")),
        cwe_code=(CWEType, Field(description="CWE-100..CWE-999 or NO_CWE")),
        analyzer_message=(str, Field(description="Max 2 sentences", max_length=300)),
    )

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a C/C++ security expert. Analyze code for vulnerabilities. "
                "Respond strictly in JSON with has_cwe, cwe_code, analyzer_message.",
            ),
            (
                "human",
                "Analyze this function for security vulnerabilities.\n\n"
                "Code:\n```c\n{code}\n```\n\n"
                "If vulnerability found: has_cwe=true, cwe_code=CWE-XXX. "
                "Else: has_cwe=false, cwe_code=NO_CWE.",
            ),
        ]
    )

    llm = ChatOpenAI(
        base_url=Settings.OPENAI_API_BASE_URL,
        api_key=Settings.OPENAI_API_KEY,
        model=Settings.OPENAI_API_MODEL,
        temperature=0.0,
    )

    try:
        chain = prompt | llm.with_structured_output(AnalysisModel)
        result = chain.invoke({"code": func_code})
        cwe_code = result.cwe_code if result.cwe_code != "NO_CWE" else None
        message = result.analyzer_message.strip()
        sentences = re.split(r"(?<=[.!?])\s+", message)
        if len(sentences) > 2:
            message = " ".join(sentences[:2])
        if cwe_code and not message.startswith(f"[{cwe_code}]"):
            message = f"[{cwe_code}] {message}"
        return {"has_cwe": result.has_cwe, "cwe_code": cwe_code, "message": message, "success": True}
    except Exception as e:
        return {"has_cwe": False, "cwe_code": None, "message": f"LLM error: {e}", "success": False}


def analyze_function_with_llm_cached(func_code: str, func_name: str, cache: dict) -> Dict[str, Any]:
    code_hash = hashlib.md5(func_code.encode()).hexdigest()
    if code_hash in cache:
        return cache[code_hash]
    result = analyze_function_with_llm(func_code, func_name)
    cache[code_hash] = result
    return result


def resolve_input(source: str) -> Path:
    """Resolve a local path or clone a GitHub URL / owner/repo shorthand."""
    p = Path(source)
    if p.exists():
        return p.resolve()

    repo_url = None
    name = None

    if source.startswith("http://") or source.startswith("https://") or source.startswith("git@"):
        repo_url = source
        parsed = urlparse(source.replace(".git", ""))
        name = Path(parsed.path).name or "repo"
    elif re.match(r"^[\w.-]+/[\w.-]+$", source):
        repo_url = f"https://github.com/{source}.git"
        name = source.split("/")[-1]
    elif re.match(r"^[\w.-]+$", source):
        # bare name: try common org, else look under projects/
        local = PROJECTS_DIR / source
        if local.exists():
            return local.resolve()
        # default guess: DaveGamble/cJSON style popular libs — require github URL
        raise typer.BadParameter(
            f"'{source}' is not a local path. Use a folder, GitHub URL, or owner/repo (e.g. DaveGamble/cJSON)."
        )

    if not repo_url:
        raise typer.BadParameter(f"Cannot resolve input: {source}")

    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    dest = PROJECTS_DIR / name
    if dest.exists() and (dest / ".git").exists():
        typer.echo(f"Using existing clone: {dest}")
        return dest.resolve()

    if dest.exists():
        shutil.rmtree(dest)

    typer.echo(f"Cloning {repo_url} -> {dest}")
    subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest)], check=True)
    return dest.resolve()


@app.command()
def analyze(
    input_source: str = typer.Argument(..., help="Local dir, GitHub URL, or owner/repo"),
    output_dir: Path = typer.Argument(..., help="Output directory for reports"),
    use_llm: bool = typer.Option(False, "--llm", help="Also run LLM analysis into llm_report.*"),
    compare: bool = typer.Option(
        True,
        "--compare/--no-compare",
        help="After SAST+LLM, compute metrics and LLM conclusion",
    ),
    llm_workers: int = typer.Option(8, "--workers"),
    batch_size: int = typer.Option(50, "--batch-size"),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
    max_files: int = typer.Option(0, "--max-files", help="Limit files scanned (0=all)"),
):
    """Run SAST (and optional LLM) into separate reports, then compare."""
    from compare_reports import run_compare_reports

    input_dir = resolve_input(input_source)
    output_dir.mkdir(parents=True, exist_ok=True)

    checkpoint_path = output_dir / CHECKPOINT_FILE
    if not resume:
        for name in (
            "sast_report.csv",
            "sast_report.jsonl",
            "sast_report.xlsx",
            "llm_report.csv",
            "llm_report.jsonl",
            "llm_report.xlsx",
            "comparison_metrics.json",
            "comparison_metrics.csv",
            "comparison_disagreements.csv",
            "comparison_conclusion.md",
            CHECKPOINT_FILE,
        ):
            p = output_dir / name
            if p.exists():
                try:
                    p.unlink()
                except PermissionError:
                    typer.echo(f"Warning: could not delete locked file {p}")

    sast_writer = BatchWriter(output_dir, "sast_report", batch_size=batch_size)
    llm_writer = BatchWriter(output_dir, "llm_report", batch_size=batch_size) if use_llm else None
    checkpoint = load_checkpoint(checkpoint_path) if resume else {}
    processed_files = set(checkpoint.get("processed_files", []))

    c_files: list[str] = []
    for root, _, files in os.walk(input_dir):
        parts = set(Path(root).parts)
        if parts & {".git", "node_modules", "build", "Build", "cmake-build-debug"}:
            continue
        for f in files:
            if f.endswith((".c", ".cpp", ".cc", ".cxx")):
                c_files.append(os.path.join(root, f))

    if max_files > 0:
        c_files = c_files[:max_files]

    typer.echo(f"Found files: {len(c_files)} (already processed: {len(processed_files)})")
    typer.echo(f"Scanners: {', '.join(get_scanners().keys())}")

    llm_tasks: List[Dict[str, Any]] = []

    with typer.progressbar(c_files, label="SAST analysis") as bar:
        for filepath in bar:
            rel_path = os.path.relpath(filepath, input_dir)
            if rel_path in processed_files:
                continue

            functions = extract_functions(filepath)
            if not functions:
                processed_files.add(rel_path)
                continue

            sast_results = run_sast_on_file(filepath)

            for func_name, info in functions.items():
                start_line = info["start"]
                end_line = info["end"]

                sast_msgs = []
                for line_num, findings in sast_results.items():
                    if start_line <= line_num <= end_line:
                        for finding in findings:
                            sast_msgs.append(
                                {
                                    "file_path": rel_path,
                                    "func_name": func_name,
                                    "has_CWE": True,
                                    "cwe_id": finding["cwe_id"] or "",
                                    "analyzer_message": finding["message"],
                                    "analyzer_type": f"SAST_{finding['analyzer'].upper()}",
                                    "line_range": f"{start_line}-{end_line}",
                                }
                            )

                if not sast_msgs:
                    sast_writer.append(
                        {
                            "file_path": rel_path,
                            "func_name": func_name,
                            "has_CWE": False,
                            "cwe_id": "",
                            "analyzer_message": "No issues found by SAST",
                            "analyzer_type": "None",
                            "line_range": f"{start_line}-{end_line}",
                        }
                    )
                else:
                    for m in deduplicate_findings(sast_msgs):
                        sast_writer.append(m)

                if use_llm:
                    masked_code = re.sub(rf"\b{re.escape(func_name)}\b", "target_function", info["code"])
                    llm_tasks.append(
                        {
                            "file_path": rel_path,
                            "func_name": func_name,
                            "code": masked_code,
                            "line_range": f"{start_line}-{end_line}",
                        }
                    )

            processed_files.add(rel_path)
            save_checkpoint(
                checkpoint_path,
                {
                    "stage": "sast_done",
                    "processed_files": list(processed_files),
                    "llm_tasks": llm_tasks if use_llm else [],
                },
            )

    sast_writer.flush()
    typer.echo(f"SAST report rows: {sast_writer.total_written} -> {sast_writer.csv_path}")

    if use_llm and llm_tasks and llm_writer is not None:
        if not LLM_AVAILABLE:
            typer.echo("LLM requested but langchain/pydantic not available.")
        else:
            cache = load_llm_cache()

            def process_task(task: Dict[str, Any]) -> Dict[str, Any]:
                llm_res = analyze_function_with_llm_cached(task["code"], task["func_name"], cache)
                return {
                    "file_path": task["file_path"],
                    "func_name": task["func_name"],
                    "has_CWE": llm_res["has_cwe"],
                    "cwe_id": llm_res.get("cwe_code") or "",
                    "analyzer_message": llm_res["message"],
                    "analyzer_type": "LLM_ANALYSIS",
                    "line_range": task["line_range"],
                }

            llm_written = 0
            with ThreadPoolExecutor(max_workers=llm_workers) as executor:
                futures = {executor.submit(process_task, t): t for t in llm_tasks}
                with typer.progressbar(as_completed(futures), label="LLM analysis", length=len(futures)) as bar:
                    for future in bar:
                        llm_writer.append(future.result())
                        llm_written += 1
                        if llm_written % batch_size == 0:
                            save_llm_cache(cache)
            save_llm_cache(cache)
            typer.echo(f"LLM report rows: {llm_written} -> {llm_writer.csv_path}")

    sast_writer.close()
    if llm_writer is not None:
        llm_writer.close()

    save_checkpoint(
        checkpoint_path,
        {
            "stage": "completed",
            "processed_files": list(processed_files),
            "sast_rows": sast_writer.total_written,
        },
    )

    typer.echo(f"\nSAST CSV: {sast_writer.csv_path.resolve()}")
    if llm_writer is not None:
        typer.echo(f"LLM CSV:  {llm_writer.csv_path.resolve()}")

    if use_llm and compare and llm_writer is not None and llm_writer.total_written > 0:
        typer.echo("\n--- Comparing SAST vs LLM reports ---")
        try:
            result = run_compare_reports(output_dir)
            m = result["metrics"]
            typer.echo(f"Agreement rate: {m['binary_agreement_rate']}")
            typer.echo(f"Compare note:   {result['conclusion_md'].resolve()}")
        except Exception as e:
            typer.echo(f"Compare failed: {e}")

    # Always write metrics/ package (same layout as benchmark example)
    try:
        from eval_metrics import write_run_metrics_package

        metrics_res = write_run_metrics_package(output_dir)
        typer.echo(f"\nMetrics folder: {metrics_res['out_dir'].resolve()}")
        typer.echo(f"Conclusion:     {metrics_res['conclusion'].resolve()}")
    except Exception as e:
        typer.echo(f"Metrics package failed: {e}")


@app.command("compare")
def compare_cmd(
    output_dir: Path = typer.Argument(..., exists=True, dir_okay=True, help="Dir with sast_report.csv + llm_report.csv"),
):
    """Compute metrics from existing SAST/LLM reports and write metrics/ package."""
    from compare_reports import run_compare_reports
    from eval_metrics import write_run_metrics_package

    try:
        result = run_compare_reports(output_dir)
    except FileNotFoundError as e:
        raise typer.BadParameter(str(e)) from e

    m = result["metrics"]
    typer.echo(f"Functions compared: {m['functions_compared']}")
    typer.echo(f"Agreement rate:     {m['binary_agreement_rate']}")
    typer.echo(f"SAST-only vulns:    {m['disagreement_sast_only']}")
    typer.echo(f"LLM-only vulns:     {m['disagreement_llm_only']}")

    metrics_res = write_run_metrics_package(output_dir)
    typer.echo(f"\nMetrics folder: {metrics_res['out_dir'].resolve()}")
    typer.echo(f"Conclusion:     {metrics_res['conclusion'].resolve()}")


@app.command("check-tools")
def check_tools():
    """Verify the three SAST analyzers are callable."""
    for name, cfg in get_scanners().items():
        cmd0 = cfg["cmd"][0]
        exists = Path(cmd0).exists() or shutil.which(cmd0) is not None
        # python script path
        if len(cfg["cmd"]) > 1 and str(cfg["cmd"][1]).endswith(".py"):
            exists = Path(cfg["cmd"][1]).exists()
        status = "OK" if exists else "MISSING"
        typer.echo(f"{name:12} [{status}]  {' '.join(cfg['cmd'][:3])}...")


@app.command("eval")
def eval_cmd(
    binary_csv: Path = typer.Argument(..., exists=True, help="ALL_binary_evaluation.csv"),
    multiclass_csv: Path = typer.Argument(..., exists=True, help="ALL_multiclass_evaluation.csv"),
    out_dir: Path = typer.Option(Path("metrics"), "--out", help="Output folder for metrics"),
    report: Optional[Path] = typer.Option(
        None, "--report", help="Optional ungrounded project report (csv/xlsx) e.g. cJSON"
    ),
):
    """Compute accuracy/precision/recall/F1 (binary) and micro/macro metrics (multiclass)."""
    from eval_metrics import export_evaluation

    res = export_evaluation(binary_csv, multiclass_csv, out_dir, ungrounded_report=report)
    typer.echo("\nBinary metrics by tool:")
    for tool, m in res["binary"]["by_tool"].items():
        typer.echo(
            f"  {tool:12} acc={m['accuracy']:.4f}  prec={m['precision']:.4f}  "
            f"rec={m['recall']:.4f}  f1={m['f1']:.4f}"
        )
    typer.echo("\nMulticlass metrics by tool:")
    for tool, m in res["multiclass"]["by_tool"].items():
        typer.echo(
            f"  {tool:12} acc={m['accuracy']:.4f}  microF1={m['micro_f1']:.4f}  "
            f"macroF1={m['macro_f1']:.4f}  weightedF1={m['weighted_f1']:.4f}"
        )
    typer.echo(f"\nWrote: {res['conclusion'].resolve()}")
    typer.echo(f"Folder: {out_dir.resolve()}")


if __name__ == "__main__":
    app()
