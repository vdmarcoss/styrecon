from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urlparse

from styrecon.core.config import ProfilesConfig
from styrecon.core.logger import log_event
from styrecon.core.runner import run_command, argv_to_cmd
from styrecon.core.scope import ScopePolicy
from styrecon.core.state.db import Db
from styrecon.utils.hashing import sha256_canonical_json
from styrecon.utils.io import write_jsonl_raw, write_jsonl_sorted
from styrecon.utils.normalize import normalize_host, normalize_url, canonicalize_url_for_hash


def _sleep(rate_limit: float) -> None:
    if rate_limit > 0:
        time.sleep(rate_limit)


def _parse_jsonl_hosts(text: str) -> List[str]:
    hosts: List[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                h = obj.get("host") or obj.get("input") or obj.get("domain")
                if h:
                    hosts.append(str(h))
                    continue
        except Exception:  # noqa: BLE001
            pass
        hosts.append(s)
    return hosts


def _run_tool(
    tool_name: str,
    argv: List[str],
    *,
    timeout_seconds: int,
    dry_run: bool,
    strict: bool,
    logger,
    out_raw_path: Path,
    rate_limit: float,
    retries: int,
    input_text: str | None = None,
):
    log_event(logger, {"event": "tool.start", "tool": tool_name, "cmd": argv_to_cmd(argv)})
    res = run_command(
        argv,
        timeout_seconds=timeout_seconds,
        dry_run=dry_run,
        retries=retries,
        input_text=input_text,
    )
    log_event(
        logger,
        {
            "event": "tool.finish",
            "tool": tool_name,
            "ok": res.ok,
            "exit_code": res.exit_code,
            "duration_ms": res.duration_ms,
            "error": res.error,
            "attempts": res.attempts,
        },
    )
    write_jsonl_raw(out_raw_path, res.stdout, res.stderr)
    _sleep(rate_limit)

    if not res.ok and strict:
        raise RuntimeError(f"{tool_name} failed: exit={res.exit_code} error={res.error}")

    return res


def run_discovery(
    *,
    db: Db,
    run_id: str,
    project: str,
    target: str,
    scope: ScopePolicy,
    profiles_cfg: ProfilesConfig,
    profile: str,
    out_dir: Path,
    logger,
    dry_run: bool,
    strict: bool,
    timeout: int,
    retries: int,
    rate_limit: float,
) -> Tuple[List[str], List[str]]:
    """
    Discovery phase (v0.1):
      - subfinder -> hosts
      - assetfinder -> hosts
      - waybackurls -> urls
    """
    prof = profiles_cfg.profiles.get(profile)
    if not prof:
        raise ValueError(f"Unknown profile: {profile}")

    steps = prof.workflow
    toolset = profiles_cfg.tools

    discovered_hosts: List[str] = []
    discovered_urls: List[str] = []

    for step in steps:
        if step.tool not in toolset:
            continue

        tdef = toolset[step.tool]
        tool_name = step.tool

        if tool_name == "subfinder":
            argv = [tdef.bin, *tdef.base_flags, *tdef.extra_flags, "-d", target]
            res = _run_tool(
                tool_name,
                argv,
                timeout_seconds=min(timeout, tdef.timeout_seconds),
                dry_run=dry_run,
                strict=strict,
                logger=logger,
                out_raw_path=out_dir / "raw" / "subfinder.jsonl",
                rate_limit=rate_limit,
                retries=retries,
            )
            if res.ok or res.stdout:
                hosts = _parse_jsonl_hosts(res.stdout)
                for h in hosts:
                    nh = normalize_host(h)
                    if not nh:
                        continue
                    if not scope.in_scope_host(nh):
                        continue
                    discovered_hosts.append(nh)

                    asset_id = db.get_or_create_asset(project=project, kind="host", value=nh, host=None)
                    data = {
                        "schema": "styrecon.observation.v1",
                        "tool": "subfinder",
                        "asset_kind": "host",
                        "host": nh,
                        "target": target,
                        "project": project,
                        "meta": {"run_profile": profile},
                        "fingerprint": {"host": nh},
                    }
                    data_hash = sha256_canonical_json(data["fingerprint"])
                    db.upsert_observation(
                        run_id=run_id,
                        asset_id=asset_id,
                        tool="subfinder",
                        data_json=json.dumps(data, ensure_ascii=False),
                        data_hash=data_hash,
                    )

        elif tool_name == "assetfinder":
            argv = [tdef.bin, *tdef.base_flags, *tdef.extra_flags, target]
            res = _run_tool(
                tool_name,
                argv,
                timeout_seconds=min(timeout, tdef.timeout_seconds),
                dry_run=dry_run,
                strict=strict,
                logger=logger,
                out_raw_path=out_dir / "raw" / "assetfinder.txt",
                rate_limit=rate_limit,
                retries=retries,
            )
            if res.ok or res.stdout:
                for line in res.stdout.splitlines():
                    nh = normalize_host(line.strip())
                    if not nh:
                        continue
                    if not scope.in_scope_host(nh):
                        continue
                    discovered_hosts.append(nh)

                    asset_id = db.get_or_create_asset(project=project, kind="host", value=nh, host=None)
                    data = {
                        "schema": "styrecon.observation.v1",
                        "tool": "assetfinder",
                        "asset_kind": "host",
                        "host": nh,
                        "target": target,
                        "project": project,
                        "meta": {"run_profile": profile},
                        "fingerprint": {"host": nh},
                    }
                    data_hash = sha256_canonical_json(data["fingerprint"])
                    db.upsert_observation(
                        run_id=run_id,
                        asset_id=asset_id,
                        tool="assetfinder",
                        data_json=json.dumps(data, ensure_ascii=False),
                        data_hash=data_hash,
                    )

        elif tool_name == "waybackurls":
            # Sin shell: waybackurls lee stdin.
            argv = [tdef.bin, *tdef.base_flags, *tdef.extra_flags]
            res = _run_tool(
                tool_name,
                argv,
                timeout_seconds=min(timeout, tdef.timeout_seconds),
                dry_run=dry_run,
                strict=False,  # wayback puede fallar; no tumbar todo el run en v0.1
                logger=logger,
                out_raw_path=out_dir / "raw" / "waybackurls.txt",
                rate_limit=rate_limit,
                retries=retries,
                input_text=f"{target}\n",
            )
            if res.ok or res.stdout:
                for line in res.stdout.splitlines():
                    u = normalize_url(line.strip())
                    if not u:
                        continue
                    parsed = urlparse(u)
                    host = normalize_host(parsed.hostname or "")
                    if not host or not scope.in_scope_host(host):
                        continue

                    discovered_urls.append(u)
                    asset_id = db.get_or_create_asset(project=project, kind="url", value=u, host=host)

                    fp = {"url": canonicalize_url_for_hash(u)}
                    data = {
                        "schema": "styrecon.observation.v1",
                        "tool": "waybackurls",
                        "asset_kind": "url",
                        "url": u,
                        "host": host,
                        "target": target,
                        "project": project,
                        "meta": {"run_profile": profile},
                        "fingerprint": fp,
                    }
                    data_hash = sha256_canonical_json(fp)
                    db.upsert_observation(
                        run_id=run_id,
                        asset_id=asset_id,
                        tool="waybackurls",
                        data_json=json.dumps(data, ensure_ascii=False),
                        data_hash=data_hash,
                    )

    hosts_unique = sorted(set(discovered_hosts))
    urls_unique = sorted(set(discovered_urls))

    write_jsonl_sorted(out_dir / "results.hosts.jsonl", [{"host": h} for h in hosts_unique], key="host")
    write_jsonl_sorted(out_dir / "results.waybackurls.jsonl", [{"url": u} for u in urls_unique], key="url")

    return hosts_unique, urls_unique