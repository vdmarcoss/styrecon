from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from styrecon.utils.normalize import normalize_host


@dataclass(frozen=True)
class ScopePolicy:
    allow: List[str]
    block: List[str]
    enabled: bool

    def in_scope_host(self, host: str) -> bool:
        if not self.enabled:
            return True
        h = normalize_host(host)
        if not h:
            return False

        # block wins
        for pat in self.block:
            if fnmatch.fnmatch(h, pat):
                return False

        # allowlist required when enabled
        for pat in self.allow:
            if fnmatch.fnmatch(h, pat):
                return True
        return False

    def describe(self) -> str:
        if not self.enabled:
            return "disabled"
        return f"allow={len(self.allow)} block={len(self.block)}"

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "allow": self.allow, "block": self.block}


def _read_scope_file(path: Path) -> List[str]:
    out: List[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lower().strip().rstrip(".")
        # normalize wildcard for subdomains
        if s.startswith("*.") and len(s) > 2:
            out.append(s)
        else:
            out.append(s)
    return out


def build_scope_policy(
    targets: Iterable[str],
    scope_allow: Optional[Path],
    scope_block: Optional[Path],
    scope_auto: bool,
    no_scope: bool,
    i_accept_risk: bool,
) -> ScopePolicy:
    if no_scope:
        if not i_accept_risk:
            raise ValueError("--no-scope requires --i-accept-risk")
        return ScopePolicy(allow=[], block=[], enabled=False)

    allow: List[str] = []
    block: List[str] = []

    if scope_allow:
        allow.extend(_read_scope_file(scope_allow))
    if scope_block:
        block.extend(_read_scope_file(scope_block))

    if scope_auto:
        for t in targets:
            root = normalize_host(t)
            if not root:
                continue
            allow.append(root)
            allow.append(f"*.{root}")

    # If scope is enabled, we require allowlist to avoid accidents
    enabled = True
    if not allow:
        raise ValueError(
            "Scope is required. Use --scope-allow PATH or --scope-auto, or disable with --no-scope --i-accept-risk."
        )

    # De-dupe
    allow = sorted(set(allow))
    block = sorted(set(block))

    return ScopePolicy(allow=allow, block=block, enabled=enabled)
