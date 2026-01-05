from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from styrecon.core.state.db import Db


@dataclass(frozen=True)
class DiffResult:
    run_a: str
    run_b: str
    added_hosts: Set[str]
    removed_hosts: Set[str]
    changed_httpx: List[Dict[str, Any]]


def _pick_runs(
    db: Db,
    project: str,
    target: str,
    profile: Optional[str],
    run_a: Optional[str],
    run_b: Optional[str],
) -> Tuple[str, str]:
    if run_a and run_b:
        return run_a, run_b

    runs = db.list_runs(project=project, target=target, profile=profile)
    if len(runs) < 2:
        raise ValueError("Need at least two runs to diff. Run 'styrecon scan' twice first.")

    # list_runs returns newest-first (DESC)
    rb = runs[0]["run_id"]  # newest
    ra = runs[1]["run_id"]  # previous
    return str(ra), str(rb)


def diff_runs(
    db: Db,
    project: str,
    target: str,
    profile: Optional[str],
    run_a: Optional[str],
    run_b: Optional[str],
) -> DiffResult:
    ra, rb = _pick_runs(db, project, target, profile, run_a, run_b)

    # Hosts diff: union of discovery tools
    tools = ["subfinder", "assetfinder"]
    a_hosts = set(db.get_hosts_for_run(ra, project=project, tools=tools))
    b_hosts = set(db.get_hosts_for_run(rb, project=project, tools=tools))

    added = b_hosts - a_hosts
    removed = a_hosts - b_hosts

    # httpx diff by hash
    a_httpx = {url: (data_json, data_hash) for url, data_json, data_hash in db.get_httpx_for_run(ra, project=project)}
    b_httpx = {url: (data_json, data_hash) for url, data_json, data_hash in db.get_httpx_for_run(rb, project=project)}

    changed: List[Dict[str, Any]] = []
    for url in sorted(set(a_httpx.keys()) & set(b_httpx.keys())):
        a_data_json, a_hash = a_httpx[url]
        b_data_json, b_hash = b_httpx[url]
        if a_hash != b_hash:
            # best-effort extract status codes for UX
            try:
                aj = json.loads(a_data_json)
                bj = json.loads(b_data_json)
                sc_a = aj.get("fingerprint", {}).get("status_code") or aj.get("result", {}).get("status_code")
                sc_b = bj.get("fingerprint", {}).get("status_code") or bj.get("result", {}).get("status_code")
            except Exception:  # noqa: BLE001
                sc_a = None
                sc_b = None
            changed.append(
                {
                    "url": url,
                    "hash_a": a_hash,
                    "hash_b": b_hash,
                    "status_code_a": sc_a,
                    "status_code_b": sc_b,
                }
            )

    return DiffResult(run_a=ra, run_b=rb, added_hosts=added, removed_hosts=removed, changed_httpx=changed)
