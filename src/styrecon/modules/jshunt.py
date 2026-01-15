# src/styrecon/modules/jshunt.py
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from rich.console import Console

from styrecon.core.config import ProfilesConfig
from styrecon.core.logger import log_event, redact_argv_for_logging
from styrecon.core.runner import argv_to_cmd, run_command
from styrecon.core.scope import ScopePolicy
from styrecon.utils.io import write_jsonl_raw, write_jsonl_sorted
from styrecon.utils.normalize import normalize_host, normalize_url

# --------- Small helpers ---------


def _sleep(rate_limit: float) -> None:
    if rate_limit and rate_limit > 0:
        time.sleep(rate_limit)


_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _sanitize_cli_text(s: str) -> str:
    """
    Remove ANSI escape sequences and carriage returns.
    (We keep raw outputs persisted to disk; this is only for console printing.)
    """
    s = s.replace("\r", "")
    s = _ANSI_RE.sub("", s)
    return s


def _detect_target_kind(target: str) -> str:
    """
    Best-effort: return "url" if target includes a scheme, otherwise "domain".
    Matches the CLI semantics in core/scope.
    """
    t = (target or "").strip()
    if "://" in t:
        try:
            p = urllib.parse.urlparse(t)
            if p.scheme and p.netloc:
                return "url"
        except Exception:  # noqa: BLE001
            pass
    return "domain"


def _parse_target_host(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        try:
            host = urllib.parse.urlparse(t).hostname or ""
        except Exception:  # noqa: BLE001
            host = ""
    else:
        host = t.split("/", 1)[0]
        host = host.split("@")[-1].split(":")[0]
    return normalize_host(host) or ""


def _target_slug(target: str) -> str:
    host = _parse_target_host(target) or "target"
    return host.replace(".", "_")


def _parse_headers_kv(headers: List[str]) -> Dict[str, str]:
    """
    Convert ["Header: value", ...] into a dict suitable for urllib.
    """
    out: Dict[str, str] = {}
    for h in headers:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        out[k] = v
    return out


def _headers_for_katana_cli(headers: List[str]) -> List[str]:
    """
    Katana expects header:value.
    We normalize "Header: value" -> "Header:value".
    """
    args: List[str] = []
    for h in headers:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        args += ["-H", f"{k}:{v}"]
    return args


def _flag_present(flags: List[str], flag: str) -> bool:
    """
    True if an argv-style list already contains the flag token (exact match).
    """
    return any(x == flag for x in (flags or []))


def _is_probably_js(url: str) -> bool:
    try:
        p = urllib.parse.urlparse(url)
    except Exception:  # noqa: BLE001
        return False
    path = (p.path or "").lower()
    return path.endswith(".js") or path.endswith(".mjs")


def _safe_segment(seg: str, *, max_len: int = 160) -> str:
    """
    Sanitize a single path segment for filesystem safety.
    """
    seg = seg.strip()
    if not seg or seg in {".", ".."}:
        return "_"
    seg = seg.replace("\\", "_").replace("/", "_")
    seg = re.sub(r"[^A-Za-z0-9._-]+", "_", seg)
    seg = seg.strip("._-") or "_"
    if len(seg) > max_len:
        h = hashlib.sha256(seg.encode("utf-8", errors="ignore")).hexdigest()[:10]
        seg = seg[: max_len - 11] + "_" + h
    return seg


def _local_path_for_url(
    *,
    base_dir: Path,
    url: str,
    target_host: str,
) -> Path:
    """
    Build a deterministic local path that mirrors the URL path.
    - For the main target host: base_dir/<url_path>
    - For other in-scope hosts: base_dir/<host>/<url_path>
    - Query string gets a short suffix to avoid collisions (only when present).
    """
    p = urllib.parse.urlparse(url)
    host = normalize_host(p.hostname or "") or ""
    path = urllib.parse.unquote(p.path or "/")

    parts = [x for x in path.split("/") if x]
    safe_parts = [_safe_segment(x) for x in parts]

    if not safe_parts:
        safe_parts = ["index.js"]

    filename = safe_parts[-1]
    if not (filename.lower().endswith(".js") or filename.lower().endswith(".mjs")):
        filename = filename + ".js"

    if p.query:
        qh = hashlib.sha256(p.query.encode("utf-8", errors="ignore")).hexdigest()[:8]
        if filename.lower().endswith(".mjs"):
            stem = filename[:-4]
            filename = f"{stem}.q{qh}.mjs"
        elif filename.lower().endswith(".js"):
            stem = filename[:-3]
            filename = f"{stem}.q{qh}.js"
        else:
            filename = f"{filename}.q{qh}"

    safe_parts[-1] = filename

    if host and target_host and host != target_host:
        safe_parts = [_safe_segment(host)] + safe_parts

    return base_dir.joinpath(*safe_parts)


def _atomic_write_bytes(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dest)


def _host_from_url(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname or ""
    except Exception:  # noqa: BLE001
        host = ""
    return normalize_host(host) or ""


def _load_live_urls_from_httpx_results(
    *,
    httpx_results_path: Path,
    scope: ScopePolicy,
) -> List[str]:
    """
    Read StyRecon results.httpx.jsonl and return "live" URLs to use as katana seeds.
    Treat any 2xx–3xx as "live".
    """
    if not httpx_results_path.exists():
        return []

    seeds: List[str] = []
    for line in httpx_results_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except Exception:  # noqa: BLE001
            continue

        sc = obj.get("status_code")
        try:
            sc_int = int(sc) if sc is not None else None
        except Exception:  # noqa: BLE001
            sc_int = None

        if sc_int is None or not (200 <= sc_int <= 399):
            continue

        u = normalize_url(obj.get("final_url") or obj.get("url") or "")
        if not u:
            continue

        host = _host_from_url(u)
        if not host or not scope.in_scope_host(host):
            continue

        seeds.append(u)

    return sorted(set(seeds))


def _iter_strings(x: object) -> Iterable[str]:
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for v in x.values():
            yield from _iter_strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from _iter_strings(v)


def _extract_url_from_katana_json(obj: dict) -> Optional[str]:
    """
    Katana JSONL format places the crawled endpoint in request.endpoint.
    Example from docs:
      { "request": { "endpoint": "https://example.com", ... }, ... }
    """
    req = obj.get("request")
    if isinstance(req, dict):
        ep = req.get("endpoint") or req.get("url")
        if isinstance(ep, str) and ep.strip():
            return ep.strip()

    # Backward/alternate formats
    for k in ("url", "endpoint", "rurl", "qurl", "input", "source"):
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()

    # Fallback: scan any string value for a URL substring
    for s in _iter_strings(obj):
        m = _URL_RE.search(s)
        if m:
            return m.group(0)

    return None


def _extract_urls_from_katana_output(stdout: str) -> List[str]:
    """
    Katana may output JSONL or plain URL lines.
    We parse defensively and extract URLs.
    """
    out: List[str] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue

        # JSONL
        if s.startswith("{") and s.endswith("}"):
            try:
                obj = json.loads(s)
            except Exception:  # noqa: BLE001
                obj = None
            if isinstance(obj, dict):
                cand = _extract_url_from_katana_json(obj)
                if isinstance(cand, str) and cand.strip():
                    out.append(cand.strip())
                continue

        # Plain URL line
        out.append(s)

    normed: List[str] = []
    for u in out:
        nu = normalize_url(u)
        if nu:
            normed.append(nu)
    return sorted(set(normed))


@dataclass(frozen=True)
class JsDownloadResult:
    url: str
    final_url: Optional[str]
    host: str
    status_code: Optional[int]
    bytes: Optional[int]
    sha256: Optional[str]
    local_path: Optional[str]
    ok: bool
    error: Optional[str]
    skipped: bool = False


# --------- Main entrypoint ---------


def run_jshunt(
    *,
    profiles_cfg: ProfilesConfig,
    scope: ScopePolicy,
    out_dir: Path,
    logger,
    project: str,
    target: str,
    headers: List[str],
    dry_run: bool,
    strict: bool,
    timeout: int,
    retries: int,
    rate_limit: float,
    js_concurrency: int,
    js_max_files: int,
    cwd: Optional[Path] = None,
    httpx_results_path: Optional[Path] = None,
    console: Optional[Console] = None,
    show_cmd: bool = True,
    show_output: bool = False,
    quiet: bool = False,
) -> List[JsDownloadResult]:
    """
    JS Hunt (live only):
    1) Read live URLs from results.httpx.jsonl (status in 2xx–3xx)
    2) Run katana to extract JS URLs
    3) Filter extracted JS URLs by ScopePolicy
    4) Download JS files concurrently to ./js_downloads/<target_slug>/
    5) Write manifest JSONL to ./js_downloads/<target_slug>/results.jshunt.jsonl
    """
    tdef = profiles_cfg.tools.get("katana")
    if not tdef:
        return []

    cwd = cwd or Path.cwd()
    target_host = _parse_target_host(target)
    target_slug = _target_slug(target)
    target_kind = _detect_target_kind(target)

    if httpx_results_path is None:
        httpx_results_path = out_dir / "results.httpx.jsonl"

    seeds = _load_live_urls_from_httpx_results(httpx_results_path=httpx_results_path, scope=scope)

    # URL-mode: ensure exact URL is included as a seed
    if target_kind == "url":
        tu = normalize_url(target)
        if tu:
            h = _host_from_url(tu)
            if h and scope.in_scope_host(h):
                seeds.append(tu)

    seeds = sorted(set(seeds))

    if console and not quiet:
        console.print(f"[dim]jshunt: seeds={len(seeds)} (from {httpx_results_path.name})[/dim]")

    if not seeds:
        return []

    (out_dir / "raw").mkdir(parents=True, exist_ok=True)

    katana_input = out_dir / "raw" / "katana.input.txt"
    katana_input.write_text("\n".join(seeds) + "\n", encoding="utf-8")

    header_args = _headers_for_katana_cli(headers)

    # Safety: URL-mode => crawl only that host (prevents out-of-scope requests)
    crawl_scope_args: List[str] = []
    if target_kind == "url":
        if not _flag_present(tdef.base_flags, "-cs") and not _flag_present(tdef.extra_flags, "-cs"):
            if target_host:
                host_re = re.escape(target_host)
                crawl_scope_args = ["-cs", rf"^https?://{host_re}(?::\d+)?/"]

    # JS-mode: make sure katana outputs only js/mjs endpoints (unless user already configured)
    ext_match_args: List[str] = []
    if not _flag_present(tdef.base_flags, "-em") and not _flag_present(tdef.extra_flags, "-em"):
        ext_match_args = ["-em", "js,mjs"]

    # If user forgot -no-default-ext-filter, add it here (js is often in default filter sets)
    ndef_args: List[str] = []
    if (
        not _flag_present(tdef.base_flags, "-no-default-ext-filter")
        and not _flag_present(tdef.base_flags, "-ndef")
        and not _flag_present(tdef.extra_flags, "-no-default-ext-filter")
        and not _flag_present(tdef.extra_flags, "-ndef")
    ):
        ndef_args = ["-no-default-ext-filter"]

    argv = [
        tdef.bin,
        *tdef.base_flags,
        *tdef.extra_flags,
        *ndef_args,
        *crawl_scope_args,
        *ext_match_args,
        *header_args,
        "-list",
        str(katana_input),
    ]

    safe_cmd = argv_to_cmd(redact_argv_for_logging(argv))
    log_event(logger, {"event": "tool.start", "tool": "katana", "cmd": safe_cmd})

    if console and (not quiet) and show_cmd:
        console.print(f"[cyan]$[/cyan] {safe_cmd}")

    if console and not quiet:
        with console.status("[cyan]Running katana (JS extraction)...[/cyan]"):
            res = run_command(
                argv,
                timeout_seconds=min(timeout, tdef.timeout_seconds),
                dry_run=dry_run,
                retries=retries,
            )
    else:
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
            "tool": "katana",
            "ok": res.ok,
            "exit_code": res.exit_code,
            "duration_ms": res.duration_ms,
            "error": res.error,
            "attempts": res.attempts,
        },
    )

    write_jsonl_raw(out_dir / "raw" / "katana.jsonl", res.stdout, res.stderr)
    _sleep(rate_limit)

    if console and not quiet:
        if res.ok:
            console.print(f"[green]✔[/green] katana finished ({res.duration_ms} ms)")
        else:
            console.print(f"[red]✖[/red] katana failed exit={res.exit_code} error={res.error}")

    if (not res.ok) and strict:
        raise RuntimeError(f"katana failed: exit={res.exit_code} error={res.error}")

    if console and (not quiet) and show_output and res.stdout:
        console.print(_sanitize_cli_text(res.stdout.rstrip("\n")), markup=False)

    extracted = _extract_urls_from_katana_output(res.stdout)

    js_urls: List[str] = []
    for u in extracted:
        host = _host_from_url(u)
        if not host or not scope.in_scope_host(host):
            continue
        if not _is_probably_js(u):
            continue
        js_urls.append(u)

    js_urls = sorted(set(js_urls))
    if js_max_files > 0:
        js_urls = js_urls[:js_max_files]

    if console and not quiet:
        console.print(f"[dim]jshunt: extracted={len(extracted)} → in_scope_js={len(js_urls)}[/dim]")

    base_dir = cwd / "js_downloads" / target_slug
    base_dir.mkdir(parents=True, exist_ok=True)

    headers_kv = _parse_headers_kv(headers)

    def _download_one(url: str) -> JsDownloadResult:
        host = _host_from_url(url)
        local_path = _local_path_for_url(base_dir=base_dir, url=url, target_host=target_host)

        local_path.parent.mkdir(parents=True, exist_ok=True)

        if dry_run:
            log_event(
                logger,
                {
                    "event": "jshunt.download",
                    "ok": True,
                    "dry_run": True,
                    "url": url,
                    "host": host,
                    "local_path": str(local_path),
                },
            )
            return JsDownloadResult(
                url=url,
                final_url=None,
                host=host,
                status_code=None,
                bytes=None,
                sha256=None,
                local_path=str(local_path),
                ok=True,
                error=None,
                skipped=False,
            )

        req = urllib.request.Request(url, headers=headers_kv, method="GET")
        last_err: Optional[str] = None

        for attempt in range(max(1, retries + 1)):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = resp.getcode()
                    final_url = resp.geturl()
                    data = resp.read()

                h = hashlib.sha256(data).hexdigest()
                _atomic_write_bytes(local_path, data)

                log_event(
                    logger,
                    {
                        "event": "jshunt.download",
                        "ok": True,
                        "attempt": attempt + 1,
                        "url": url,
                        "final_url": final_url,
                        "host": host,
                        "status_code": status,
                        "bytes": len(data),
                        "sha256": h,
                        "local_path": str(local_path),
                    },
                )

                return JsDownloadResult(
                    url=url,
                    final_url=final_url,
                    host=host,
                    status_code=int(status) if status is not None else None,
                    bytes=len(data),
                    sha256=h,
                    local_path=str(local_path),
                    ok=True,
                    error=None,
                    skipped=False,
                )

            except Exception as e:  # noqa: BLE001
                last_err = str(e)
                log_event(
                    logger,
                    {
                        "event": "jshunt.download",
                        "ok": False,
                        "attempt": attempt + 1,
                        "url": url,
                        "host": host,
                        "error": last_err,
                        "local_path": str(local_path),
                    },
                )
                time.sleep(0.2 * (attempt + 1))

        return JsDownloadResult(
            url=url,
            final_url=None,
            host=host,
            status_code=None,
            bytes=None,
            sha256=None,
            local_path=str(local_path),
            ok=False,
            error=last_err,
            skipped=False,
        )

    results: List[JsDownloadResult] = []

    if not js_urls:
        manifest = base_dir / "results.jshunt.jsonl"
        write_jsonl_sorted(manifest, [], key="url")
        return []

    workers = max(1, int(js_concurrency or 1))
    if console and not quiet:
        console.print(f"[dim]jshunt: downloading with concurrency={workers} into {base_dir}[/dim]")

    ok_count = 0
    fail_count = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_download_one, u): u for u in js_urls}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            if r.ok:
                ok_count += 1
            else:
                fail_count += 1

    results.sort(key=lambda x: x.url)

    manifest_path = base_dir / "results.jshunt.jsonl"
    export = [
        {
            "schema": "styrecon.jshunt.v1",
            "project": project,
            "target": target,
            "url": r.url,
            "final_url": r.final_url,
            "host": r.host,
            "status_code": r.status_code,
            "bytes": r.bytes,
            "sha256": r.sha256,
            "local_path": r.local_path,
            "ok": r.ok,
            "error": r.error,
            "skipped": r.skipped,
        }
        for r in results
    ]
    write_jsonl_sorted(manifest_path, export, key="url")

    if console and not quiet:
        console.print(
            f"[green]✔[/green] jshunt: downloaded={ok_count} failed={fail_count} "
            f"[dim](manifest: {manifest_path})[/dim]"
        )

    if strict and fail_count > 0:
        raise RuntimeError(f"jshunt: {fail_count} downloads failed (see manifest: {manifest_path})")

    return results