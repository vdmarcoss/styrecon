from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from styrecon.utils.normalize import normalize_host


def detect_target_kind(target: str) -> str:
    """
    Returns "url" if the target looks like a URL (contains scheme), else "domain".
    """
    s = (target or "").strip()
    return "url" if "://" in s else "domain"


def extract_target_host(target: str) -> str:
    """
    Extract a hostname suitable for scope/discovery tools.

    - If target is URL: parse hostname (drops port automatically via urlparse.hostname).
    - If target is domain-ish: normalize; strip port if present (example.com:8443 -> example.com).
    """
    s = (target or "").strip()
    if not s:
        return ""

    if "://" in s:
        try:
            p = urlparse(s)
        except Exception:  # noqa: BLE001
            return ""
        h = p.hostname or ""
        return normalize_host(h)

    # If user accidentally passes a path without scheme, keep it safe: only take host part.
    if "/" in s:
        s = s.split("/", 1)[0]

    # Strip :port if numeric
    if ":" in s:
        host_part, port_part = s.rsplit(":", 1)
        if port_part.isdigit():
            s = host_part

    return normalize_host(s)


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
            kind = detect_target_kind(t)
            host = extract_target_host(t)
            if not host:
                continue

            # Always allow the exact host
            allow.append(host)

            # Only add wildcard for domain targets (URL targets must not expand scope)
            if kind == "domain":
                allow.append(f"*.{host}")

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

def detect_target_kind(target: str) -> str:
    """Returns 'url' if scheme is present, else 'domain'."""
    return "url" if "://" in target else "domain"


def extract_target_host(target: str) -> Optional[str]:
    """Extracts host from URL or returns the domain string."""
    if "://" in target:
        try:
            return normalize_host(urlparse(target).hostname or "")
        except Exception:
            return None
    return normalize_host(target)