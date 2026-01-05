from __future__ import annotations

import re
import unicodedata
from typing import Iterable, List, Optional
from urllib.parse import urlparse, urlunparse


_WS_RE = re.compile(r"\s+")


def normalize_host(host: str) -> str:
    if not host:
        return ""
    h = host.strip().lower().rstrip(".")
    # remove surrounding brackets for IPv6 like [::1]
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # reject spaces
    if any(c.isspace() for c in h):
        return ""
    return h


def normalize_url(url: str) -> str:
    if not url:
        return ""
    u = url.strip()
    u = unicodedata.normalize("NFKC", u)
    if not u:
        return ""
    # If host-only, ignore (url normalization expects scheme)
    if "://" not in u:
        return ""
    try:
        p = urlparse(u)
    except Exception:  # noqa: BLE001
        return ""
    if not p.scheme or not p.netloc:
        return ""
    scheme = p.scheme.lower()
    netloc = p.netloc.strip()
    # drop fragment
    fragment = ""
    path = p.path or "/"
    # keep query for stored url; hashing will strip query separately
    return urlunparse((scheme, netloc, path, p.params, p.query, fragment))


def canonicalize_url_for_hash(url: str) -> str:
    """
    Canonical form for hashing:
      - drop query + fragment
      - ensure path
      - ensure explicit port (80/443)
      - lowercase host
    """
    u = normalize_url(url)
    if not u:
        return ""
    p = urlparse(u)
    scheme = p.scheme.lower()
    netloc = p.netloc

    # split userinfo
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    host_port = netloc
    host = host_port
    port = None
    if ":" in host_port:
        host, port_s = host_port.rsplit(":", 1)
        if port_s.isdigit():
            port = int(port_s)
    host = normalize_host(host)

    if port is None:
        port = 443 if scheme == "https" else 80

    path = p.path or "/"
    return urlunparse((scheme, f"{host}:{port}", path, "", "", ""))


def normalize_title(title: str) -> str:
    if not title:
        return ""
    s = unicodedata.normalize("NFKC", title)
    s = _WS_RE.sub(" ", s).strip().lower()
    if len(s) > 200:
        s = s[:200].rstrip()
    return s


def content_type_mime(ct: str) -> str:
    if not ct:
        return ""
    s = ct.strip().lower()
    if ";" in s:
        s = s.split(";", 1)[0].strip()
    return s


def normalize_webserver(ws: str) -> str:
    if not ws:
        return ""
    s = unicodedata.normalize("NFKC", ws).strip().lower()
    s = _WS_RE.sub(" ", s)
    if len(s) > 120:
        s = s[:120].rstrip()
    return s


def normalize_tech_list(tech: Iterable) -> List[str]:
    out: List[str] = []
    for t in tech:
        if not t:
            continue
        s = unicodedata.normalize("NFKC", str(t)).strip().lower()
        if not s:
            continue
        out.append(s)
    # de-dupe + sort
    return sorted(set(out))
