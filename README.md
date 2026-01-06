# StyRecon — Pura Vida Ops 🇨🇷

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

> [!CAUTION]
> **Use StyRecon only on targets you are authorized to test.**  
> The authors are not responsible for any misuse or damage caused by this tool.

**StyRecon** (`styrecon`) is an open-source **Python** CLI that orchestrates a modern bug bounty recon toolchain with a **stateful** and **scope-aware** approach.

Instead of running tools in isolation, StyRecon captures the “state” of your targets, enabling safe recon workflows and diffs between runs — while enforcing scope guardrails to reduce out-of-scope accidents.

---

## 🚀 Key Features (v0.1)

### 🛡️ Scope Guardrails (Safety First)
- **Target mode:** Automatically distinguishes between:
  - **Domain mode** → discovery + verify
  - **URL mode** → strict host probing (no subdomain expansion by default)
- **Auto-scope:** `--scope-auto` builds a conservative allowlist based on your target.
- **Allow/Block patterns:** Use scope allow/block files to avoid forbidden subdomains or out-of-scope assets.
- **Risk acknowledgement:** Disabling scope requires `--no-scope --i-accept-risk`.

### 🧠 Stateful Recon (SQLite)
- **SQLite backend:** Runs, assets, and observations are stored structurally.
- **Smart diffing:** Compare runs to spot new hosts and meaningful HTTP fingerprint changes.
- **Redaction by design:** Sensitive headers (`Authorization`, `Cookie`, `X-API-Key`, etc.) are automatically redacted from CLI command display and logs.

### 🛠️ Execution Profiles
- **`passive`**: OSINT discovery (`subfinder`, `assetfinder`, `waybackurls`)
- **`verify`**: Discovery + fingerprinting (`whatweb`, runs first) + HTTP probing (`httpx-toolkit`)

> Note: `waybackurls` output is stored as an artifact and **is not verified by httpx** in v0.1 (by design to avoid noise).

---

## 🚧 In Development
Planned but **not shipped** in v0.1:
- `ffuf` integration (active content discovery)
- `feroxbuster` integration (active directory/content discovery)
- **Wayback-Verify**: sampling and probing Wayback URLs with strict limits/rate-limiting

---

## 🛠️ Requirements

StyRecon orchestrates external binaries. Ensure the following are available in your `$PATH`:

| Tool | Purpose | Source |
| :--- | :--- | :--- |
| `subfinder` | Passive subdomain discovery | https://github.com/projectdiscovery/subfinder |
| `assetfinder` | Host discovery | https://github.com/tomnomnom/assetfinder |
| `waybackurls` | Historic URL OSINT | https://github.com/tomnomnom/waybackurls |
| `httpx-toolkit` | HTTP probing & tech detect | https://github.com/projectdiscovery/httpx |
| `whatweb` | Web technology fingerprinting | https://github.com/urbanadventurer/WhatWeb |

---

## ⚙️ Installation

```bash
git clone <REPO_URL>
cd styrecon

python -m venv .venv
source .venv/bin/activate

pip install -e .
```

### Verify:
```bash
styrecon --help
```

---

## 📖 Usage Examples

- 1) Passive scan (domain)
```bash
styrecon scan target.com \
  --project my_bug_bounty \
  --profile passive \
  --scope-auto
```

- 2) Verify a domain (discovery + http probe) + adding headers required in the bug hunter program with option `-H`
```bash
styrecon scan target.com \
  --profiles config/profiles.yaml \
  --project my_bug_bounty \
  --profile verify \
  --scope-auto \
  -H "X-H1-traffic: myuser" \
  --out .runtime/runs \
  --db .runtime/styrecon.sqlite \
  --rate-limit 0.2 \
  --timeout 1200 \
  --retries 1 \
  --verbose

```

- 3) Verify an exact URL (URL mode)
```bash
# URL mode skips subdomain discovery and probes only the URL host (seeded)
styrecon scan "https://api.target.com/v1" \
  --project my_bug_bounty \
  --profile verify \
  --scope-auto \
  -H "X-H1-traffic: myuser"
```

- 4) Diff runs
```bash
# Compare the last two runs for a target
styrecon diff target.com \
  --project my_bug_bounty \
  --profile verify \
  --db .runtime/styrecon.sqlite
```


- 5) Dry-run (prints commands, executes nothing)
```bash
styrecon scan target.com \
  --project my_bug_bounty \
  --profile verify \
  --scope-auto \
  -H "Authorization: Bearer <token>" \
  --dry-run \
  --verbose

# Secrets are redacted in CLI/logs.
```

---

## 📁 Output Structure
All data is stored in `.runtime/` (recommended to keep gitignored):
- `.runtime/styrecon.sqlite` — central state store (runs, assets, observations)
- `.runtime/runs/{project}/{target}/{run_id}/`
    - `run.log` — execution log (redacted)
    - `raw/` — raw tool outputs (subfinder.jsonl, httpx.jsonl, etc.)
    - `results.hosts.jsonl` — cleaned/unique hosts
    - `results.waybackurls.jsonl` — cleaned/unique Wayback URLs
    - `results.httpx.jsonl` — summarized httpx results (verify profile)

---

## 🗺️ Roadmap
- `ffuf` & `feroxbuster` integration (active scanning, opt-in with guardrails)
- Wayback-Verify (sampling + rate-limited probing)
- Export to Markdown/HTML reports
- Integration tests for scan/diff pipelines

---

## License
- See `LICENSE`.

---

## 🇨🇷 Pura Vida Ops
Built for reproducibility, safety, and practical bug bounty workflows.