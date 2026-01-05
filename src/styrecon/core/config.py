from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass(frozen=True)
class ToolDef:
    name: str
    bin: str
    base_flags: List[str]
    extra_flags: List[str]
    timeout_seconds: int


@dataclass(frozen=True)
class WorkflowStep:
    step_id: str
    tool: str
    input_from: Optional[str] = None


@dataclass(frozen=True)
class ProfileDef:
    name: str
    description: str
    workflow: List[WorkflowStep]


@dataclass(frozen=True)
class ProfilesConfig:
    tools: Dict[str, ToolDef]
    profiles: Dict[str, ProfileDef]


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    return [str(value)]


def load_profiles_config(path: Path) -> ProfilesConfig:
    if not path.exists():
        raise FileNotFoundError(f"profiles.yaml not found: {path}")

    raw: Dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_tools: Dict[str, Any] = raw.get("tools", {}) or {}
    raw_profiles: Dict[str, Any] = raw.get("profiles", {}) or {}

    tools: Dict[str, ToolDef] = {}
    for name, t in raw_tools.items():
        tools[name] = ToolDef(
            name=name,
            bin=str(t.get("bin", name)),
            base_flags=_as_list(t.get("base_flags")),
            extra_flags=_as_list(t.get("extra_flags")),
            timeout_seconds=int(t.get("timeout_seconds", 300)),
        )

    profiles: Dict[str, ProfileDef] = {}
    for pname, p in raw_profiles.items():
        wf: List[WorkflowStep] = []
        for step in p.get("workflow", []) or []:
            wf.append(
                WorkflowStep(
                    step_id=str(step.get("step_id")),
                    tool=str(step.get("tool")),
                    input_from=step.get("input_from"),
                )
            )
        profiles[pname] = ProfileDef(
            name=pname,
            description=str(p.get("description", "")),
            workflow=wf,
        )

    return ProfilesConfig(tools=tools, profiles=profiles)
