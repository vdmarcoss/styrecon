from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Iterable, List


REDACT_KEYS = {
    "authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "proxy-authorization",
}


def build_run_logger(log_path: Path, verbose: bool = False) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Usa el directorio del run (run_id) para que sea único.
    run_name = log_path.parent.name
    logger = logging.getLogger(f"styrecon.run.{run_name}")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Cierra handlers existentes (evita fugas)
    for h in list(logger.handlers):
        try:
            h.close()
        except Exception:  # noqa: BLE001
            pass
    logger.handlers.clear()

    logger.propagate = False

    fh = logging.FileHandler(str(log_path), encoding="utf-8")
    fh.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(fh)

    return logger


def redact_headers_for_display(headers: Iterable[str]) -> List[str]:
    """
    Returns headers safe to persist in run.meta.json and logs.
    Keeps keys; redacts sensitive values.
    """
    out: List[str] = []
    for h in headers:
        if ":" not in h:
            # Header inválido/inesperado: no lo persistimos tal cual.
            out.append("<redacted>")
            continue
        k, v = h.split(":", 1)
        k_clean = k.strip()
        v_clean = v.strip()
        if k_clean.lower() in REDACT_KEYS:
            out.append(f"{k_clean}: <redacted>")
        else:
            out.append(f"{k_clean}: {v_clean}")
    return out


def redact_argv_for_logging(argv: List[str]) -> List[str]:
    """
    Redacts sensitive header values passed via:
      -H "Key: Value"
      --header "Key: Value"
      --header=Key: Value

    NOTE: Only redacts when header key matches REDACT_KEYS.
    """
    out: List[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]

        # Case 1: --header=Key: Value
        if tok.startswith("--header="):
            raw = tok.split("=", 1)[1]
            red = redact_headers_for_display([raw])
            out.append("--header=" + (red[0] if red else "<redacted>"))
            i += 1
            continue

        out.append(tok)

        # Case 2: -H "Key: Value" or --header "Key: Value"
        if tok in ("-H", "--header") and i + 1 < len(argv):
            header = argv[i + 1]
            red = redact_headers_for_display([header])
            out.append(red[0] if red else "<redacted>")
            i += 2
            continue

        i += 1

    return out


def log_event(logger: logging.Logger, event: Dict) -> None:
    logger.info(json.dumps(event, ensure_ascii=False, sort_keys=True))
