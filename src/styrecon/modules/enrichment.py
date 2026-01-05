# src/styrecon/modules/enrichment.py
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List

from styrecon.core.config import ProfilesConfig
from styrecon.core.logger import log_event
from styrecon.core.runner import argv_to_cmd, run_command
from styrecon.core.scope import ScopePolicy
from styrecon.core.state.db import Db
from styrecon.utils.hashing import sha256_canonical_json
from styrecon.utils.io import write_jsonl_raw, write_jsonl_sorted
from styrecon.utils.normalize import (
    canonicalize_url_for_hash,
    content_type_mime,
    normalize_host,
    normalize_title,
    normalize_url,
    normalize_tech_list,
    normalize_webserver,
)


def _sleep(rate_limit: float) -> None:
    if rate_limit > 0:
        time.sleep(rate_limit)


def _httpx_hash_input(obj: Dict) -> Dict:
    """
    Build the canonical fingerprint dict used for hashing.
    Designed to avoid false positives (rtt, ip changes, timestamps ignored).
    """
    url = normalize_url(obj.get("url") or obj.get("input") or "")
    final_url = normalize_url(obj.get("final_url") or obj.get("finalUrl") or obj.get("location") or url)

    sc = obj.get("status_code") or obj.get("status-code") or obj.get("status_code_int")
    try:
        sc_int = int(sc) if sc is not None else None
    except Exception:  # noqa: BLE001
        sc_int = None

    title_norm = normalize_title(obj.get("title") or "")
    ct_mime = content_type_mime(obj.get("content_type") or obj.get("content-type") or "")

    webserver_norm = normalize_webserver(obj.get("webserver") or obj.get("web-server") or "")
    tech_norm = normalize_tech_list(obj.get("tech") or obj.get("technologies") or obj.get("tech_detect") or [])

    # redirects: keep only hosts (stable)
    redirect_hosts: List[str] = []
    chain = obj.get("chain") or obj.get("redirect_chain") or []
    if isinstance(chain, list):
        for item in chain:
            if isinstance(item, str):
                h = item.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0]
                nh = normalize_host(h)
                if nh:
                    redirect_hosts.append(nh)
    redirect_hosts = sorted(set(redirect_hosts))

    hash_input: Dict = {
        "status_code": sc_int,
        "final_url": canonicalize_url_for_hash(final_url or url),
    }
    if title_norm:
        hash_input["title_norm"] = title_norm
    if ct_mime:
        hash_input["content_type_mime"] = ct_mime
    if webserver_norm:
        hash_input["webserver_norm"] = webserver_norm
    if tech_norm:
        hash_input["tech_norm"] = tech_norm
    if redirect_hosts:
        hash_input["redirect_hosts"] = redirect_hosts

    return hash_input


def run_httpx_verify(
    *,
    db: Db,
    run_id: str,
    project: str,
    target: str,
    scope: ScopePolicy,
    profiles_cfg: ProfilesConfig,
    out_dir: Path,
    logger,
    hosts: List[str],
    headers: List[str],
    dry_run: bool,
    strict: bool,
    timeout: int,
    retries: int,
    rate_limit: float,
) -> List[str]:
    prof = profiles_cfg.profiles.get("verify")
    if not prof:
        raise ValueError("verify profile not found in profiles.yaml")

    tdef = profiles_cfg.tools.get("httpx")
    if not tdef:
        raise ValueError("httpx tool not defined in profiles.yaml")

    # httpx-toolkit supports -l input file; avoid /bin/sh pipes for robustness.
    scoped_hosts = [h for h in hosts if scope.in_scope_host(h)]
    scoped_hosts = sorted(set(scoped_hosts))

    # Write input file for reproducibility
    input_path = out_dir / "raw" / "httpx.input.txt"
    input_path.write_text("\n".join(scoped_hosts) + "\n", encoding="utf-8")

    # Build httpx command (direct)
    header_args: List[str] = []
    for h in headers:
        if ":" not in h:
            continue
        header_args += ["-H", h]

    argv = [tdef.bin, "-l", str(input_path), *tdef.base_flags, *tdef.extra_flags, *header_args]

    log_event(logger, {"event": "tool.start", "tool": "httpx", "cmd": argv_to_cmd(argv)})
    res = run_command(
        argv,
        timeout_seconds=min(timeout, tdef.timeout_seconds),
        dry_run=dry_run,
        retries=retries,
    )
    log_event(
        logger,
        {
            "event": "tool.finish",
            "tool": "httpx",
            "ok": res.ok,
            "exit_code": res.exit_code,
            "duration_ms": res.duration_ms,
            "error": res.error,
            "attempts": res.attempts,
        },
    )
    write_jsonl_raw(out_dir / "raw" / "httpx.jsonl", res.stdout, res.stderr)
    _sleep(rate_limit)

    if not res.ok and strict:
        raise RuntimeError(f"httpx failed: exit={res.exit_code} error={res.error}")

    # Parse JSONL output (best-effort; may be partial on timeout)
    urls_seen: List[str] = []
    export_by_url: Dict[str, Dict] = {}

    for line in res.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except Exception:  # noqa: BLE001
            continue

        url = normalize_url(obj.get("url") or obj.get("input") or "")
        if not url:
            continue

        host = url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0]
        host = normalize_host(host)
        if not host or not scope.in_scope_host(host):
            continue

        hash_input = _httpx_hash_input(obj)
        data_hash = sha256_canonical_json(hash_input)

        stored = {
            "schema": "styrecon.observation.v1",
            "tool": "httpx",
            "asset_kind": "url",
            "url": url,
            "host": host,
            "result": {
                "status_code": hash_input.get("status_code"),
                "final_url": hash_input.get("final_url"),
                "title": obj.get("title") or "",
                "content_type": obj.get("content_type") or obj.get("content-type") or "",
                "webserver": obj.get("webserver") or obj.get("web-server") or "",
                "tech": obj.get("tech") or obj.get("technologies") or [],
            },
            "volatile": {
                "ip": obj.get("ip") or obj.get("a") or None,
                "rtt_ms": obj.get("rtt") or obj.get("response_time") or None,
                "timestamp_utc": obj.get("time") or None,
            },
            "fingerprint": hash_input,
            "target": target,
            "project": project,
            "meta": {"run_profile": "verify"},
        }

        asset_id = db.get_or_create_asset(project=project, kind="url", value=url, host=host)
        db.upsert_observation(
            run_id=run_id,
            asset_id=asset_id,
            tool="httpx",
            data_json=json.dumps(stored, ensure_ascii=False),
            data_hash=data_hash,
        )

        urls_seen.append(url)
        export_by_url[url] = {
            "url": url,
            "host": host,
            "status_code": hash_input.get("status_code"),
            "final_url": hash_input.get("final_url"),
            "title_norm": hash_input.get("title_norm"),
            "webserver_norm": hash_input.get("webserver_norm"),
            "tech_norm": hash_input.get("tech_norm"),
            "hash": data_hash,
        }

    urls_seen = sorted(set(urls_seen))
    write_jsonl_sorted(out_dir / "results.httpx.jsonl", list(export_by_url.values()), key="url")
    return urls_seen
