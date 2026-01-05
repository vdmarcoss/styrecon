from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any, Dict


def _strip_nones(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            v2 = _strip_nones(v)
            if v2 is None:
                continue
            if v2 == "" or v2 == [] or v2 == {}:
                continue
            out[k] = v2
        return out
    if isinstance(obj, list):
        return [x for x in (_strip_nones(v) for v in obj) if x is not None]
    return obj


def canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    obj2 = _strip_nones(obj)
    s = json.dumps(obj2, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    s = unicodedata.normalize("NFKC", s)
    return s.encode("utf-8")


def sha256_canonical_json(obj: Dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(canonical_json_bytes(obj))
    return h.hexdigest()
