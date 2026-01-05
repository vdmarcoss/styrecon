# src/styrecon/core/runner.py
from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union


@dataclass(frozen=True)
class CommandResult:
    argv: List[str]
    ok: bool
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    error: Optional[str] = None
    attempts: int = 1


def _now_ms() -> int:
    return int(time.time() * 1000)


def _decode_maybe_bytes(x: Union[str, bytes, None]) -> str:
    if x is None:
        return ""
    if isinstance(x, bytes):
        return x.decode("utf-8", errors="replace")
    if isinstance(x, str):
        return x
    return ""


def run_command(
    argv: List[str],
    timeout_seconds: int,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
    dry_run: bool = False,
    input_text: Optional[str] = None,
    retries: int = 0,
) -> CommandResult:
    start_total = _now_ms()

    if dry_run:
        return CommandResult(
            argv=argv,
            ok=True,
            exit_code=0,
            duration_ms=0,
            stdout="",
            stderr="",
            error=None,
            attempts=1,
        )

    last: Optional[CommandResult] = None
    attempts = max(1, int(retries) + 1)

    for attempt_idx in range(attempts):
        try:
            p = subprocess.run(
                argv,
                cwd=str(cwd) if cwd else None,
                env=env,
                input=input_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
            end_total = _now_ms()
            res = CommandResult(
                argv=argv,
                ok=(p.returncode == 0),
                exit_code=p.returncode,
                duration_ms=end_total - start_total,
                stdout=p.stdout or "",
                stderr=p.stderr or "",
                error=None,
                attempts=attempt_idx + 1,
            )
            last = res
            if res.ok:
                return res

        except subprocess.TimeoutExpired as exc:
            end_total = _now_ms()
            res = CommandResult(
                argv=argv,
                ok=False,
                exit_code=124,
                duration_ms=end_total - start_total,
                stdout=_decode_maybe_bytes(exc.stdout),
                stderr=_decode_maybe_bytes(exc.stderr),
                error="timeout",
                attempts=attempt_idx + 1,
            )
            last = res

        except FileNotFoundError:
            end_total = _now_ms()
            return CommandResult(
                argv=argv,
                ok=False,
                exit_code=127,
                duration_ms=end_total - start_total,
                stdout="",
                stderr="",
                error="command_not_found",
                attempts=attempt_idx + 1,
            )

        # backoff mínimo si quedan intentos
        if attempt_idx < attempts - 1:
            time.sleep(0.25 * (2**attempt_idx))

    return last or CommandResult(
        argv=argv,
        ok=False,
        exit_code=1,
        duration_ms=_now_ms() - start_total,
        stdout="",
        stderr="",
        error="unknown_error",
        attempts=attempts,
    )


def argv_to_cmd(argv: List[str]) -> str:
    return " ".join(shlex.quote(x) for x in argv)
