#!/usr/bin/env python3
"""RATS-compatible C/C++ scanner using the official RATS vulnerability database.

Produces XML matching the shape expected by `rats --xml` so existing parsers work
on Windows without compiling the original C tool.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent
DB_FILES = [ROOT / "rats-c.xml", ROOT / "rats-openssl.xml"]

CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NAME_RE = re.compile(r"<Name>\s*([^<]+?)\s*</Name>", re.IGNORECASE)


def load_vuln_names() -> dict[str, str]:
    names: dict[str, str] = {}
    for db in DB_FILES:
        if not db.exists():
            continue
        text = db.read_text(encoding="utf-8", errors="ignore")
        for match in NAME_RE.finditer(text):
            name = match.group(1).strip()
            if name:
                names[name] = f"RATS: potentially unsafe use of {name}"
    return names


def scan_file(path: Path, vuln_db: dict[str, str]) -> list[tuple[int, str, str]]:
    findings: list[tuple[int, str, str]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue
        for match in CALL_RE.finditer(line):
            fname = match.group(1)
            if fname in vuln_db:
                findings.append((i, fname, vuln_db[fname]))
    return findings


def emit_xml(results: list[tuple[str, int, str, str]]) -> str:
    parts = ['<?xml version="1.0"?>', "<rats_output>"]
    for filepath, line, name, _msg in results:
        parts.append("  <vulnerability>")
        parts.append(f"    <file>{escape(filepath)}</file>")
        parts.append(f"    <line>{line}</line>")
        parts.append(f"    <name>{escape(name)}</name>")
        parts.append("  </vulnerability>")
    parts.append("</rats_output>")
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description="RATS-compatible XML scanner")
    parser.add_argument("--xml", action="store_true", help="Emit XML (always on)")
    parser.add_argument("targets", nargs="+", help="Files or directories to scan")
    args = parser.parse_args()

    vuln_db = load_vuln_names()
    if not vuln_db:
        print('<?xml version="1.0"?><rats_output/>')
        return 1

    results: list[tuple[str, int, str, str]] = []
    for target in args.targets:
        p = Path(target)
        files: list[Path] = []
        if p.is_dir():
            for ext in ("*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp"):
                files.extend(p.rglob(ext))
        elif p.is_file():
            files.append(p)

        for f in files:
            for line, name, msg in scan_file(f, vuln_db):
                results.append((str(f), line, name, msg))

    sys.stdout.write(emit_xml(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
