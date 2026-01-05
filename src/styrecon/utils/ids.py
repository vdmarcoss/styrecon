from __future__ import annotations

import os
import time


_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode_base32(n: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_CROCKFORD[n & 31])
        n >>= 5
    return "".join(reversed(out))


def new_run_id() -> str:
    """
    ULID-like, sortable enough for CLI usage:
      - 10 chars time + 16 chars randomness (Crockford base32)
    """
    ms = int(time.time() * 1000)
    time_part = _encode_base32(ms, 10)
    rand_part = _encode_base32(int.from_bytes(os.urandom(10), "big"), 16)
    return f"{time_part}{rand_part}"
