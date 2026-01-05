from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RunRow:
    run_id: str
    project: str
    target: str
    profile: str
    status: str
    started_at_utc: str
    finished_at_utc: Optional[str]
    cli_command: str
    config_json: str
