from __future__ import annotations

import json
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich.console import Console
from rich.table import Table

from styrecon.core.config import ProfilesConfig, load_profiles_config
from styrecon.core.logger import build_run_logger, log_event, redact_headers_for_display
from styrecon.core.scope import ScopePolicy, build_scope_policy
from styrecon.core.state.db import DEFAULT_DB_PATH, Db, ensure_db_initialized
from styrecon.core.state.diff import diff_runs
from styrecon.modules.discovery import run_discovery
from styrecon.modules.enrichment import run_httpx_verify
from styrecon.utils.ids import new_run_id

app = typer.Typer(no_args_is_help=True)
console = Console()


def _safe_cli_command(argv: List[str]) -> str:
    """
    Build a command-line string safe to persist (redacts sensitive header values).

    Notes:
      - Redacts values for headers like Authorization/Cookie/X-API-Key, etc.
      - Uses shell-style quoting so it can be copy/pasted for debugging.
    """
    out: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-H", "--header"):
            out.append(a)
            if i + 1 < len(argv):
                hdr = argv[i + 1]
                safe = redact_headers_for_display([hdr])
                out.append(safe[0] if safe else "<redacted>")
                i += 2
                continue
        out.append(a)
        i += 1
    return " ".join(shlex.quote(x) for x in out)


def _read_lines(path: Optional[Path]) -> List[str]:
    if not path:
        return []
    if not path.exists():
        raise FileNotFoundError(str(path))
    out: List[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def _collect_headers(headers: List[str], headers_file: Optional[Path]) -> List[str]:
    out: List[str] = []
    for h in headers:
        if not h:
            continue
        out.append(h.strip())
    out.extend(_read_lines(headers_file))
    # de-dupe (preserve order)
    seen = set()
    uniq: List[str] = []
    for h in out:
        if h in seen:
            continue
        seen.add(h)
        uniq.append(h)
    return uniq


def _default_profiles_path() -> Path:
    cwd_candidate = Path.cwd() / "config" / "profiles.yaml"
    if cwd_candidate.exists():
        return cwd_candidate

    here = Path(__file__).resolve()
    repo_candidate = here.parents[3] / "config" / "profiles.yaml"
    if repo_candidate.exists():
        return repo_candidate

    raise FileNotFoundError(
        "profiles.yaml not found. Provide --profiles (e.g. --profiles config/profiles.yaml)."
    )



def _ensure_outdir(base: Path, project: str, target: str, run_id: str) -> Path:
    safe_project = project.replace("/", "_")
    safe_target = target.replace("/", "_")
    out_dir = base / safe_project / safe_target / run_id
    (out_dir / "raw").mkdir(parents=True, exist_ok=True)
    return out_dir


def _render_runs_table(rows: List[Dict[str, Any]]) -> None:
    t = Table(title="Runs")
    t.add_column("run_id", style="cyan")
    t.add_column("project")
    t.add_column("target")
    t.add_column("profile")
    t.add_column("status")
    t.add_column("started_at_utc")
    t.add_column("finished_at_utc")
    t.add_column("warnings")
    t.add_column("errors")
    for r in rows:
        t.add_row(
            str(r.get("run_id", "")),
            str(r.get("project", "")),
            str(r.get("target", "")),
            str(r.get("profile", "")),
            str(r.get("status", "")),
            str(r.get("started_at_utc", "")),
            str(r.get("finished_at_utc", "")) if r.get("finished_at_utc") else "",
            str(r.get("warnings_count", 0)),
            str(r.get("errors_count", 0)),
        )
    console.print(t)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target root domain (e.g., example.com)"),
    project: str = typer.Option("default", "--project", "-p", help="Project name"),
    profile: str = typer.Option("passive", "--profile", help="Profile name from profiles.yaml"),
    profiles_path: Path = typer.Option(None, "--profiles", help="Path to profiles.yaml (default: config/profiles.yaml)"),
    out_base: Path = typer.Option(Path(".runtime/runs"), "--out", help="Base output directory"),
    db_path: Path = typer.Option(DEFAULT_DB_PATH, "--db", help="SQLite DB path"),
    scope_allow: Optional[Path] = typer.Option(None, "--scope-allow", help="Allowlist file (one host/pattern per line)"),
    scope_block: Optional[Path] = typer.Option(None, "--scope-block", help="Blocklist file (one host/pattern per line)"),
    scope_auto: bool = typer.Option(False, "--scope-auto", help="Auto-allow target and its subdomains"),
    no_scope: bool = typer.Option(False, "--no-scope", help="Disable scope (requires --i-accept-risk)"),
    i_accept_risk: bool = typer.Option(False, "--i-accept-risk", help="Required when using --no-scope"),
    header: List[str] = typer.Option([], "--header", "-H", help="Custom header (repeatable), e.g. -H 'X-Hackerone: sty10x'"),
    headers_file: Optional[Path] = typer.Option(None, "--headers-file", help="File with headers (one per line)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Do not execute tools; only create run record + folders"),
    strict: bool = typer.Option(False, "--strict", help="Fail the run if a tool exits non-zero"),
    timeout: int = typer.Option(600, "--timeout", help="Max seconds per tool (cap)"),
    retries: int = typer.Option(0, "--retries", help="Retries per tool (v0.1 placeholder)"),
    rate_limit: float = typer.Option(0.0, "--rate-limit", help="Sleep between tool runs (seconds)"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logging"),
):
    """
    Run a scan using a profile workflow (v0.1).
    """
    profiles_path = profiles_path or _default_profiles_path()
    profiles_cfg: ProfilesConfig = load_profiles_config(profiles_path)

    # scope policy
    scope: ScopePolicy = build_scope_policy(
        targets=[target],
        scope_allow=scope_allow,
        scope_block=scope_block,
        scope_auto=scope_auto,
        no_scope=no_scope,
        i_accept_risk=i_accept_risk,
    )

    # headers (persist redacted)
    headers = _collect_headers(header, headers_file)
    headers_redacted = redact_headers_for_display(headers)

    ensure_db_initialized(db_path)

    run_id = new_run_id()
    out_dir = _ensure_outdir(out_base, project, target, run_id)
    log_path = out_dir / "run.log"
    logger = build_run_logger(log_path, verbose=verbose)

    # Persist a safe CLI command string (redacts secrets)
    cli_cmd = _safe_cli_command(sys.argv)

    # minimal config snapshot for run record
    config_snapshot = {
        "profiles_path": str(profiles_path),
        "profile": profile,
        "target": target,
        "project": project,
        "scope": scope.to_dict(),
        "headers": headers_redacted,
        "options": {
            "dry_run": dry_run,
            "strict": strict,
            "timeout": timeout,
            "retries": retries,
            "rate_limit": rate_limit,
        },
    }

    warnings_count = 0
    errors_count = 0

    with Db(db_path) as db:
        db.insert_run(
            run_id=run_id,
            project=project,
            target=target,
            profile=profile,
            status="running",
            cli_command=cli_cmd,
            config_json=json.dumps(config_snapshot, ensure_ascii=False),
            scope_allow_path=str(scope_allow) if scope_allow else None,
            scope_block_path=str(scope_block) if scope_block else None,
        )

        log_event(logger, {"event": "run.start", "run_id": run_id, "project": project, "target": target, "profile": profile, "scope": scope.describe()})

        try:
            hosts, _urls = run_discovery(
                db=db,
                run_id=run_id,
                project=project,
                target=target,
                scope=scope,
                profiles_cfg=profiles_cfg,
                profile=profile,
                out_dir=out_dir,
                logger=logger,
                dry_run=dry_run,
                strict=strict,
                timeout=timeout,
                retries=retries,
                rate_limit=rate_limit,
            )

            # httpx verify step only if profile exists and includes it
            if profile == "verify":
                run_httpx_verify(
                    db=db,
                    run_id=run_id,
                    project=project,
                    target=target,
                    scope=scope,
                    profiles_cfg=profiles_cfg,
                    out_dir=out_dir,
                    logger=logger,
                    hosts=hosts,
                    headers=headers,
                    dry_run=dry_run,
                    strict=strict,
                    timeout=timeout,
                    retries=retries,
                    rate_limit=rate_limit,
                )

            db.update_run_status(run_id, "finished", warnings_count=warnings_count, errors_count=errors_count)
            log_event(logger, {"event": "run.finish", "run_id": run_id, "status": "finished"})
            console.print(f"[green]OK[/green] run_id={run_id} out={out_dir}")

        except Exception as exc:  # noqa: BLE001
            errors_count += 1
            db.update_run_status(run_id, "failed", warnings_count=warnings_count, errors_count=errors_count)
            log_event(logger, {"event": "run.finish", "run_id": run_id, "status": "failed", "error": str(exc)})
            raise


@app.command()
def runs(
    target: str = typer.Argument(..., help="Target root domain"),
    project: str = typer.Option("default", "--project", "-p"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    db_path: Path = typer.Option(DEFAULT_DB_PATH, "--db"),
):
    """
    List runs for (project,target).
    """
    ensure_db_initialized(db_path)
    with Db(db_path) as db:
        rows = db.list_runs(project=project, target=target, profile=profile)
    _render_runs_table(rows)


@app.command()
def diff(
    target: str = typer.Argument(..., help="Target root domain"),
    project: str = typer.Option("default", "--project", "-p"),
    profile: Optional[str] = typer.Option(None, "--profile", help="Filter by profile"),
    run_a: Optional[str] = typer.Option(None, "--run-a", help="Older run_id"),
    run_b: Optional[str] = typer.Option(None, "--run-b", help="Newer run_id"),
    db_path: Path = typer.Option(DEFAULT_DB_PATH, "--db"),
):
    """
    Diff two runs (default: last two runs for target).
    """
    ensure_db_initialized(db_path)
    with Db(db_path) as db:
        res = diff_runs(db=db, project=project, target=target, profile=profile, run_a=run_a, run_b=run_b)

    console.print(f"[cyan]Diff[/cyan] {res.run_a} -> {res.run_b}")

    if res.added_hosts:
        console.print(f"[green]Added hosts ({len(res.added_hosts)}):[/green]")
        for h in sorted(res.added_hosts):
            console.print(f"  + {h}")

    if not res.added_hosts and not res.removed_hosts and not res.changed_httpx:
        console.print("[green]No changes detected.[/green]")
        return

    if res.removed_hosts:
        console.print(f"[red]Removed hosts ({len(res.removed_hosts)}):[/red]")
        for h in sorted(res.removed_hosts):
            console.print(f"  - {h}")

    if res.changed_httpx:
        console.print(f"[yellow]Changed httpx ({len(res.changed_httpx)}):[/yellow]")
        for row in res.changed_httpx:
            console.print(f"  * {row['url']}  {row.get('status_code_a')} -> {row.get('status_code_b')}")
