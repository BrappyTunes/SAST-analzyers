#!/usr/bin/env python3
"""Resolve local SAST tool binaries (Windows-friendly)."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
TOOLS = PROJECT_ROOT / "tools"
PYTHON = sys.executable


def _which(name: str) -> str | None:
    return shutil.which(name)


def cppcheck_cmd() -> list[str]:
    candidates = [
        _which("cppcheck"),
        r"C:\Program Files\Cppcheck\cppcheck.exe",
        r"C:\Program Files (x86)\Cppcheck\cppcheck.exe",
        str(TOOLS / "cppcheck" / "cppcheck.exe"),
    ]
    for c in candidates:
        if c and Path(c).exists():
            return [c]
    return ["cppcheck"]


def flawfinder_cmd() -> list[str]:
    local = TOOLS / "flawfinder" / "flawfinder.py"
    if local.exists():
        return [PYTHON, str(local)]
    w = _which("flawfinder")
    if w:
        return [w]
    return ["flawfinder"]


def rats_cmd() -> list[str]:
    local = TOOLS / "rats" / "rats_scan.py"
    if local.exists():
        return [PYTHON, str(local)]
    w = _which("rats")
    if w:
        return [w]
    return ["rats"]


def scanners_config() -> dict:
    return {
        "cppcheck": {
            "cmd": cppcheck_cmd()
            + ["--enable=warning,performance,portability,style", "--xml", "--xml-version=2", "{target}"],
            "stderr": True,
        },
        "flawfinder": {
            "cmd": flawfinder_cmd() + ["--csv", "--quiet", "{target}"],
            "stderr": False,
        },
        "rats": {
            "cmd": rats_cmd() + ["--xml", "{target}"],
            "stderr": False,
        },
    }
