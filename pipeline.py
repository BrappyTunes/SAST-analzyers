#!/usr/bin/env python3
import os
import re
import csv
import json
import hashlib
import random
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

import typer
import pandas as pd

try:
    from src.core.config import Settings
except ImportError:
    class Settings:
        OPENAI_API_BASE_URL = "http://localhost:11434/v1"
        OPENAI_API_KEY = "dummy-key"
        OPENAI_API_MODEL = "qwen2.5-coder"

try:
    from pydantic import Field
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI
    from pydantic import create_model
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

app = typer.Typer(help="CLI для оценки Juliet Test Suite (Binary + Multiclass)", add_completion=False)

LLM_CACHE_FILE = ".llm_cache.json"
RESULTS_DIR = Path("results")

SAST_CACHE: Dict[str, Dict[int, List[Dict[str, Any]]]] = {}


def extract_ground_truth(filepath: str, func_name: str) -> Dict[str, str]:
    text_to_check = f"{os.path.basename(filepath)} {func_name}".lower()

    is_good = "_good_" in text_to_check or func_name.lower().startswith("good")
    is_bad = "_bad_" in text_to_check or func_name.lower().startswith("bad")

    match = re.search(r'cwe(\d{3})', text_to_check)
    cwe_from_name = f"CWE-{match.group(1)}" if match else "NO_CWE"

    if is_good:
        binary_gt = "NON_VULNERABLE"
        multiclass_gt = "NO_CWE"
    elif is_bad:
        binary_gt = "VULNERABLE"
        multiclass_gt = cwe_from_name
    else:
        binary_gt = "NON_VULNERABLE"
        multiclass_gt = "NO_CWE"

    return {"binary": binary_gt, "multiclass": multiclass_gt}


def load_llm_cache() -> dict:
    if os.path.exists(LLM_CACHE_FILE):
        try:
            with open(LLM_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_llm_cache(cache: dict):
    with open(LLM_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def extract_functions(filepath: str) -> Dict[str, Dict[str, Any]]:
    functions = {}
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        current_func = None
        brace_count = 0
        start_line = 0
        func_lines = []

        for i, line in enumerate(lines, 1):
            func_match = re.match(
                r'(?:static\s+)?(?:void|int|char|float|double|bool|long|short|unsigned|signed)\s*\*?\s+(\w+)\s*\([^)]*\)\s*\{?',
                line
            )
            if func_match and brace_count == 0:
                current_func = func_match.group(1)
                start_line = i
                func_lines = [line]
                brace_count = line.count('{') - line.count('}')
            elif current_func:
                func_lines.append(line)
                brace_count += line.count('{') - line.count('}')
                if brace_count == 0:
                    functions[current_func] = {
                        "start": start_line,
                        "end": i,
                        "code": "".join(func_lines)
                    }
                    current_func = None
                    func_lines = []
    except Exception as e:
        typer.echo(f"Warning: failed to read {filepath}: {e}")
    return functions


def build_func_rename_map(functions: Dict[str, Dict[str, Any]], filepath: str) -> Dict[str, str]:
    rename_map = {}
    counter = 1
    file_lower = os.path.basename(filepath).lower()
    for func_name in functions.keys():
        lower_name = func_name.lower()
        text_to_check = f"{file_lower} {lower_name}"
        if "_good_" in text_to_check or lower_name.startswith("good") or "_bad_" in text_to_check or lower_name.startswith("bad"):
            rename_map[func_name] = f"func{counter}"
            counter += 1
    return rename_map


try:
    from tools_paths import scanners_config as _scanners_config
    SCANNERS_CONFIG = _scanners_config()
except ImportError:
    SCANNERS_CONFIG = {
        "cppcheck": {"cmd": ["cppcheck", "--enable=warning,performance", "--xml", "--xml-version=2", "{target}"], "stderr": True},
        "flawfinder": {"cmd": ["flawfinder", "--csv", "--quiet", "{target}"], "stderr": False},
        "rats": {"cmd": ["rats", "--xml", "{target}"], "stderr": False},
    }


def extract_cwe_from_text(text: str) -> str:
    match = re.search(r'CWE[-_]?\s*(\d{3})', text, re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else "NO_CWE"


def run_sast_on_file(filepath: str) -> Dict[int, List[Dict[str, Any]]]:
    results = {}
    filename = os.path.basename(filepath)

    for name, cfg in SCANNERS_CONFIG.items():
        cmd = [filepath if p == "{target}" else p for p in cfg["cmd"]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
            output = r.stderr if cfg.get("stderr") else r.stdout

            if name == "cppcheck":
                try:
                    for err in ET.fromstring(output).findall('.//error'):
                        msg = err.get('msg') or err.get('verbose', 'Unknown')
                        cwe_attr = err.get('cwe')
                        pred_cwe = f"CWE-{cwe_attr}" if cwe_attr else extract_cwe_from_text(msg)

                        for loc in err.findall('location'):
                            if os.path.basename(loc.get('file', '')) == filename:
                                line = int(loc.get('line', 0))
                                if line > 0:
                                    results.setdefault(line, []).append({"tool": name, "message": msg, "pred_cwe": pred_cwe})
                except ET.ParseError:
                    pass
            elif name == "flawfinder":
                for row in csv.DictReader(output.splitlines()):
                    if os.path.basename(row.get('File', '')) == filename:
                        line = int(row.get('Line', 0))
                        msg = row.get('Message', row.get('Context', 'Unknown'))
                        if line > 0:
                            results.setdefault(line, []).append({"tool": name, "message": msg, "pred_cwe": extract_cwe_from_text(msg)})
            elif name == "rats":
                try:
                    for vuln in ET.fromstring(output).findall('.//vulnerability'):
                        file_elem = vuln.find('file')
                        line_elem = vuln.find('line')
                        if file_elem is not None and os.path.basename(file_elem.text or '') == filename:
                            if line_elem is not None and line_elem.text:
                                line = int(line_elem.text)
                                msg = vuln.find('name').text if vuln.find('name') is not None else "RATS vulnerability"
                                if line > 0:
                                    results.setdefault(line, []).append({"tool": name, "message": msg, "pred_cwe": extract_cwe_from_text(msg)})
                except ET.ParseError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return results


def analyze_function_with_llm(func_code: str) -> Dict[str, Any]:
    if not LLM_AVAILABLE:
        return {"pred_cwe": "NO_CWE", "success": False}

    AnalysisModel = create_model(
        'FunctionAnalysis',
        pred_cwe=(str, Field(description="Specific CWE code like CWE-121, CWE-476, or exactly 'NO_CWE' if safe"))
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a C/C++ security expert. Respond strictly in JSON. Predict the EXACT CWE category (e.g., CWE-121, CWE-476). If the code is safe or has no vulnerability, you MUST output 'NO_CWE'."),
        ("human", "Analyze this function:\n\n```c\n{code}\n```")
    ])

    llm = ChatOpenAI(base_url=Settings.OPENAI_API_BASE_URL, api_key=Settings.OPENAI_API_KEY, model=Settings.OPENAI_API_MODEL, temperature=0.0)

    try:
        chain = prompt | llm.with_structured_output(AnalysisModel)
        result = chain.invoke({"code": func_code})

        pred = result.pred_cwe.strip().upper()
        pred = pred.replace(",", "").replace(" ", "")
        if pred == "NO_CWE" or "NO_CWE" in pred:
            pred = "NO_CWE"
        elif not pred.startswith("CWE-"):
            pred = f"CWE-{pred.replace('CWE', '')}"

        return {"pred_cwe": pred, "success": True}
    except Exception as e:
        return {"pred_cwe": "ERROR", "success": False}


def analyze_function_with_llm_cached(func_code: str, cache: dict) -> Dict[str, Any]:
    code_hash = hashlib.md5(func_code.encode()).hexdigest()
    if code_hash in cache:
        return cache[code_hash]
    result = analyze_function_with_llm(func_code)
    cache[code_hash] = result
    return result


def map_to_binary(pred_cwe: str) -> str:
    return "VULNERABLE" if pred_cwe != "NO_CWE" and pred_cwe != "ERROR" else "NON_VULNERABLE"


def mask_function_code(code: str, func_name: str, rename_map: Dict[str, str]) -> str:
    masked = code
    for orig_name, new_name in rename_map.items():
        masked = re.sub(rf'\b{re.escape(orig_name)}\b', new_name, masked)
    if func_name not in rename_map:
        masked = re.sub(rf'\b{re.escape(func_name)}\b', 'target_function', masked)
    return masked


def process_single_function(task: Dict[str, Any], use_llm: bool, llm_cache: dict, input_dir: Path) -> tuple:
    filepath = task["filepath"]
    func_name = task["func_name"]
    info = task["info"]
    gt = task["gt"]
    sast_results = task["sast_results"]
    rename_map = task["rename_map"]
    rel_path = os.path.relpath(filepath, input_dir)

    binary_rows = []
    multiclass_rows = []

    func_sast_findings = []
    for line_num, findings in sast_results.items():
        if info["start"] <= line_num <= info["end"]:
            func_sast_findings.extend(findings)

    seen = set()
    unique_sast = []
    for f in func_sast_findings:
        key = (f["tool"], f["pred_cwe"])
        if key not in seen:
            seen.add(key)
            unique_sast.append(f)

    if not unique_sast:
        for tool in SCANNERS_CONFIG.keys():
            unique_sast.append({"tool": tool, "pred_cwe": "NO_CWE", "message": "No issues found"})

    for finding in unique_sast:
        pred_mc = finding["pred_cwe"]
        pred_bin = map_to_binary(pred_mc)

        binary_rows.append({
            "file": rel_path, "func": func_name, "tool": finding["tool"],
            "gt_binary": gt["binary"], "pred_binary": pred_bin,
            "message": finding["message"]
        })
        multiclass_rows.append({
            "file": rel_path, "func": func_name, "tool": finding["tool"],
            "gt_multiclass": gt["multiclass"], "pred_multiclass": pred_mc,
            "message": finding["message"]
        })

    if use_llm:
        masked_code = mask_function_code(info["code"], func_name, rename_map)
        llm_res = analyze_function_with_llm_cached(masked_code, llm_cache)
        pred_mc = llm_res["pred_cwe"]
        pred_bin = map_to_binary(pred_mc)

        binary_rows.append({
            "file": rel_path, "func": func_name, "tool": "LLM",
            "gt_binary": gt["binary"], "pred_binary": pred_bin,
            "message": "LLM Generated"
        })
        multiclass_rows.append({
            "file": rel_path, "func": func_name, "tool": "LLM",
            "gt_multiclass": gt["multiclass"], "pred_multiclass": pred_mc,
            "message": "LLM Generated"
        })

    return binary_rows, multiclass_rows


@app.command()
def analyze(
    input_dir: Path = typer.Argument(..., exists=True, dir_okay=True, readable=True),
    use_llm: bool = typer.Option(False, "--llm"),
    workers: int = typer.Option(8, "--workers", help="Количество потоков для анализа"),
    sample: int = typer.Option(100, "--sample", help="Количество случайных файлов для анализа (0 = все файлы)"),
):
    binary_dir = RESULTS_DIR / "binary"
    multiclass_dir = RESULTS_DIR / "multiclass"
    binary_dir.mkdir(parents=True, exist_ok=True)
    multiclass_dir.mkdir(parents=True, exist_ok=True)

    typer.echo("Сканирование файлов...")
    c_files = [os.path.join(root, f) for root, _, files in os.walk(input_dir) for f in files if f.endswith(('.c', '.cpp'))]
    
    total_files = len(c_files)
    if sample > 0 and total_files > sample:
        typer.echo(f"Случайная выборка: отобрано {sample} файлов из {total_files}")
        c_files = random.sample(c_files, sample)
    else:
        typer.echo(f"Найдено файлов для анализа: {total_files}")

    cwe_groups = defaultdict(list)

    with typer.progressbar(c_files, label="Индексация") as bar:
        for filepath in bar:
            functions = extract_functions(filepath)
            rename_map = build_func_rename_map(functions, filepath)
            for func_name, info in functions.items():
                gt = extract_ground_truth(filepath, func_name)
                cwe_id = gt["multiclass"]
                cwe_groups[cwe_id].append({
                    "filepath": filepath,
                    "func_name": func_name,
                    "info": info,
                    "gt": gt,
                    "rename_map": rename_map
                })

    typer.echo(f"Найдено {len(cwe_groups)} уникальных CWE категорий.")

    llm_cache = load_llm_cache()

    for cwe_id, tasks in cwe_groups.items():
        typer.echo(f"Обработка категории: {cwe_id} ({len(tasks)} функций)")

        unique_files = list(set(t["filepath"] for t in tasks))
        with typer.progressbar(unique_files, label=f"SAST сканирование файлов для {cwe_id}") as bar:
            for fpath in bar:
                if fpath not in SAST_CACHE:
                    SAST_CACHE[fpath] = run_sast_on_file(fpath)

        for t in tasks:
            t["sast_results"] = SAST_CACHE[t["filepath"]]

        cwe_binary_rows = []
        cwe_multiclass_rows = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(process_single_function, t, use_llm, llm_cache, input_dir)
                for t in tasks
            ]

            with typer.progressbar(as_completed(futures), label=f"Анализ функций {cwe_id}") as bar:
                for future in bar:
                    bin_rows, multi_rows = future.result()
                    cwe_binary_rows.extend(bin_rows)
                    cwe_multiclass_rows.extend(multi_rows)

        safe_cwe_name = cwe_id.replace('-', '_').replace(' ', '_')
        bin_file = binary_dir / f"{safe_cwe_name}_binary.csv"
        multi_file = multiclass_dir / f"{safe_cwe_name}_multiclass.csv"

        if not bin_file.exists():
            pd.DataFrame(columns=["file", "func", "tool", "gt_binary", "pred_binary", "message"]).to_csv(bin_file, index=False)
        if not multi_file.exists():
            pd.DataFrame(columns=["file", "func", "tool", "gt_multiclass", "pred_multiclass", "message"]).to_csv(multi_file, index=False)

        if cwe_binary_rows:
            pd.DataFrame(cwe_binary_rows).to_csv(bin_file, mode='a', header=False, index=False)
        if cwe_multiclass_rows:
            pd.DataFrame(cwe_multiclass_rows).to_csv(multi_file, mode='a', header=False, index=False)

        typer.echo(f"Сохранено: {bin_file.name} и {multi_file.name}")

        if use_llm:
            save_llm_cache(llm_cache)

    typer.echo("Финальная сводка по всем сохраненным файлам...")

    all_bin_files = list(binary_dir.glob("*_binary.csv"))
    all_multi_files = list(multiclass_dir.glob("*_multiclass.csv"))

    if all_bin_files:
        df_bin = pd.concat((pd.read_csv(f) for f in all_bin_files), ignore_index=True)
        df_bin['is_correct'] = df_bin['gt_binary'] == df_bin['pred_binary']
        typer.echo("\n--- Binary Accuracy (Vulnerable vs Non-Vulnerable) ---")
        typer.echo(df_bin.groupby('tool')['is_correct'].mean().round(4).to_string())
        df_bin.to_csv(binary_dir / "ALL_binary_evaluation.csv", index=False)

    if all_multi_files:
        df_multi = pd.concat((pd.read_csv(f) for f in all_multi_files), ignore_index=True)
        df_multi['is_correct'] = df_multi['gt_multiclass'] == df_multi['pred_multiclass']
        typer.echo("\n--- Multiclass Accuracy (Exact CWE match) ---")
        typer.echo(df_multi.groupby('tool')['is_correct'].mean().round(4).to_string())
        df_multi.to_csv(multiclass_dir / "ALL_multiclass_evaluation.csv", index=False)

    typer.echo(f"Все результаты сохранены в: {RESULTS_DIR.resolve()}")


if __name__ == "__main__":
    app()
