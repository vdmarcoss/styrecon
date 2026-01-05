from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl_raw(path: Path, stdout: str, stderr: str) -> None:
    """
    Writes tool raw stdout/stderr to a single file in a simple forensic-friendly format.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        if stdout:
            f.write(stdout.rstrip() + "\n")
        if stderr:
            f.write("\n# --- STDERR ---\n")
            f.write(stderr.rstrip() + "\n")


def write_jsonl_sorted(path: Path, rows: List[Dict[str, Any]], key: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows2 = sorted(rows, key=lambda r: str(r.get(key, "")))
    with path.open("w", encoding="utf-8") as f:
        for r in rows2:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
