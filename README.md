# StyRecon — Pura Vida Ops

> **Use only on targets you are authorized to test.**

**StyRecon** (`styrecon`) is an open-source **Python** CLI that orchestrates common bug bounty recon tools in a **scope-aware** and **stateful** way:
- **Scope-aware:** allow/block patterns to prevent accidental scanning.
- **Stateful:** stores runs + observations in **SQLite**, enabling diffs between runs.
- **Reproducible:** deterministic artifacts (JSONL) + run logs.

It is designed to run locally (e.g., a Kali Linux VM) and orchestrate external binaries via `subprocess` (no Python wrappers, no chatops).

---

## Features (v0.1)

### ✅ Profiles: `passive` / `verify`
- **passive**
  - `subfinder` → hosts
  - `assetfinder` → hosts
  - `waybackurls` → URLs (stored as artifacts)
- **verify**
  - Everything from `passive`
  - `httpx-toolkit` → HTTP probing (low noise)
  - `whatweb` runs **first** to quickly fingerprint the target

### ✅ Scope guardrails
- `--scope-auto` builds a conservative allowlist from the target.
- Optional allow/block files.
- `--no-scope` requires `--i-accept-risk`.

### ✅ URL vs Domain target handling
- If the target is a **URL** (`https://...`), StyRecon switches to **URL mode**:
  - Skips `subfinder` / `assetfinder` (no subdomain expansion by default)
  - Seeds verification from the URL host
- If the target is a **domain**, StyRecon runs discovery + verify normally.

### ✅ Safe logging & secret redaction
- Headers like `Authorization`, `Cookie`, `X-API-Key`, etc. are redacted in:
  - CLI displayed commands
  - Logs
  - Metadata files

### ✅ Outputs you can diff and automate
- Run artifacts in `.runtime/runs/...`
- SQLite DB inventory in `.runtime/styrecon.sqlite`

---

## In Development 🚧
These features are planned but **not shipped** in v0.1:
- `ffuf` (active content discovery)
- `feroxbuster` (active directory/content discovery)
- `waybackurls-verify` (optionally verify sampled Wayback URLs with httpx)

> Active scanning will be **opt-in** with strict guardrails (rate limits, caps, safety switches).

---

## Requirements

### Python
- Python `>= 3.10`

### External tools (must be in `$PATH`)
- `subfinder`
- `assetfinder`
- `waybackurls`
- `httpx-toolkit` (httpx)
- `whatweb`

> Install these using your preferred method (e.g., `go install`, distro packages, or official releases).

---

## Install

### From source (recommended for now)
```bash
git clone <your-repo-url>
cd styrecon

python -m venv .venv
source .venv/bin/activate

pip install -e .
```

### Verify:
```bash
styrecon --help
```