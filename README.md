# Crossfire

**MCP & A2A Security Proxy with Real-Time Threat Detection**

Crossfire is a transparent man-in-the-middle proxy that sits between your IDE and MCP servers, detecting credential theft, prompt injection, data exfiltration, and 7 other attack patterns in real time. It also intercepts A2A (Agent-to-Agent) protocol traffic over HTTP.

### Virtual environment (recommended)

Crossfire does **not** require a venv, but you **should** use one so `pip install -e .` does not mix with system or other projects’ packages (especially if you install the **`gemini`** extra).

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[gemini]"        # or: pip install -e .
```

`.venv/` is listed in `.gitignore`. In Cursor, select **Python: Select Interpreter** → `./.venv/bin/python` for this workspace.

## Quick Start (pip — recommended)

**You do not need Node or npm** for the MCP proxy: `pip install crossfire-mcp` adds both **`crossfire`** and **`crossfire-proxy`** console scripts next to your Python (same venv). Run `crossfire install` from that environment so `mcp.json` gets the **absolute path** to `crossfire-proxy` (works even when Cursor has a minimal `PATH`).

```bash
python3 -m venv .venv
source .venv/bin/activate                    # Windows: .venv\Scripts\activate

# Install Crossfire (core detectors + dashboard API; no Gemini SDK)
pip install -e .
# When published to PyPI:  pip install crossfire-mcp

# Optional: Gemini enrichment (GOOGLE_API_KEY or CROSSFIRE_GEMINI_KEY)
# pip install -e ".[gemini]"

# Build the React dashboard once (needed for the full UI on :9999; or use Vite dev on :5173 only)
cd dashboard && npm install && npm run build && cd ..

# Rewrite MCP configs to use crossfire-proxy, then start the dashboard
crossfire install
crossfire dashboard
# Open http://localhost:9999
# crossfire ping          # smoke-test event without MCP
# crossfire ping --threat # + sample critical threat

# Demo (poisoned MCP server):  bash demo/run-demo.sh
```

**PyPI wheels:** Before `python -m build` / publishing, copy the built UI into the package so the wheel ships static assets:

```bash
cd dashboard && npm ci && npm run build && cd ..
python3 scripts/sync_dashboard_dist.py
python -m build
```

(`server/web_dist/` is gitignored; editable installs still use `dashboard/dist` from the repo.)

## MCP config & what Crossfire sees

Crossfire’s **stdio proxy** only applies to MCP servers defined with a **`command`** (and optional `args`). The installer rewrites those so traffic flows through **`crossfire-proxy`** (the **pip** console script, or the optional Node shim) before your real server.

- **URL-only MCP** (`url` set, no `command`): the IDE talks to a remote endpoint directly. **`crossfire install` skips these** — Crossfire cannot sit in the middle without a local process. Use stdio-based servers if you need inspection.
- **Config locations** (all are scanned; the same file on disk is only processed once):
  - **Cursor:** `~/.cursor/mcp.json` and project `.cursor/mcp.json` (relative to cwd when you run `crossfire install`)
  - **VS Code:** `~/.vscode/mcp.json` and project `.vscode/mcp.json`
  - **Windsurf (Codeium):** `~/.codeium/windsurf/mcp_config.json`
  - **Google Antigravity:** `~/.gemini/antigravity/mcp_config.json`
  - **Claude Desktop:** OS-specific paths under Application Support / `.config` (see `proxy/installer.py`)

**Diagnostics:** `crossfire doctor` prints each known config path (if present), classifies each server (proxied / stdio not proxied / URL-only), and checks the dashboard (`/health`, `/api/guardian`). Run the dashboard first (`crossfire dashboard`) for a full green check.

### If MCP servers won’t start or configs don’t look proxied

- Use the **same Python/venv** where you ran **`pip install -e .`**: activate it, then **`crossfire install`**. The installer prefers **`crossfire-proxy` next to `sys.executable`**, so `mcp.json` stores a full path that Cursor can run without relying on shell `PATH`.
- If you still see warnings, ensure **`crossfire-proxy` exists** (e.g. `ls "$(dirname $(which python3))/crossfire-proxy"`).
- **`crossfire start` restores MCP configs on exit (Ctrl+C).** For a persistent setup, use **`crossfire install`** and **`crossfire dashboard`** instead of the one-shot flow.

### npm / `npx` (thin shim — installs Python from PyPI)

The npm package **`crossfire-mcp`** ships only **`bin/`** scripts plus a **`postinstall`** hook. On install it runs **`pipx install crossfire-mcp`** (preferred) or **`pip install --user crossfire-mcp`**, so the real **`crossfire`** and **`crossfire-proxy`** CLIs come from **PyPI** (bundled dashboard in the wheel). **You do not need a git clone** for the published npm package.

```bash
# Use `--` so "dashboard" / "doctor" are passed to Crossfire, not to npx:
npx --yes crossfire-mcp@0.1.0 -- dashboard
npx --yes crossfire-mcp@0.1.0 -- doctor

# Global install (ensure $(npm prefix -g)/bin is on your PATH):
# npm install -g crossfire-mcp && crossfire dashboard
```

If you see `sh: crossfire-mcp: command not found`, use the `--` form above, or install the Python package directly: `pip install crossfire-mcp` then `crossfire doctor`.

**From a git clone:** if **`pyproject.toml`** is present next to **`package.json`**, **`postinstall`** uses **`pip install -e .`** into **`.venv/`** (development layout).

**Publishing the wheel first:** `npx` users need the **`crossfire-mcp`** Python package on PyPI (same name as the npm package). Build the UI, sync, and upload the wheel (see **PyPI wheels** above) before **`npm publish`**.

### Seeing traffic (dashboard)

| Step | What to do |
|------|------------|
| **Smoke test (no MCP)** | Start `crossfire dashboard`, then run **`crossfire ping`**. The Traffic Log should show one event (`server`: `ping`). Use **`crossfire ping --threat`** to also post a sample **critical** threat (demo). The UI **loads past events on connect** (`GET /api/events`); `POST /api/events` accepts **one JSON object per request** (not a JSON array). |
| **Real MCP traffic** | Add **stdio** MCP servers (`command` + `args`), run **`crossfire install`**, **restart the IDE**, then use a chat that **invokes tools** (not just text). URL-only MCP is not proxied. |
| **Dashboard URL** | If the proxy and UI are not on `http://localhost:9999`, set **`CROSSFIRE_DASHBOARD_URL`** (or `dashboard.url` in `crossfire.yaml`) and restart the IDE. |
| **Config not found** | The IDE often runs MCP with a **cwd** that is not your repo root, so `crossfire.yaml` is skipped. **Fix:** set **`CROSSFIRE_CONFIG`** to the full path of your `crossfire.yaml`, or set **`CROSSFIRE_DASHBOARD_URL`** in the MCP server `env` block. The proxy also checks the repo root **next to the installed `proxy` package** (after cwd and before `~/.crossfire.yaml`). |

### Active vulnerability scan (no IDE)

Runs **`initialize` → `tools/list` → synthetic `tools/call` probes** and applies the same detectors as the live proxy (description poisoning, rules, response secret patterns, cross-call chains).

```bash
crossfire scan --cmd "python3 demo/poisoned_weather.py"
crossfire scan --server myserver          # resolve command from MCP configs
crossfire scan --all                      # every stdio server in configs
crossfire scan --cmd "python3 demo/poisoned_weather.py" --json
```

With **`crossfire dashboard`** running, trigger a scan via **`POST /api/scan`** with `{"server_name":"..."}` or `{"command":["python3","demo/poisoned_weather.py"]}`. Progress appears on **`WebSocket /ws`** as `scan_progress` and `scan_complete`; **`GET /api/scan/results`** returns recent reports. (A dashboard “Scan” button can call the same API.)

**Figma design URLs:** Crossfire records **MCP JSON-RPC** (e.g. `tools/call` with `fileKey` / node id in **arguments**). Opening a file in the **browser** at `https://www.figma.com/design/...` does not go through the MCP proxy; you will see the design when you **invoke a Figma MCP tool** that references that file (check the Traffic Log / raw params).

## Architecture

```
IDE (Cursor, VS Code, Windsurf, Antigravity, Claude, …)
  │ stdin/stdout (JSON-RPC)
  ▼
┌─────────────────────┐
│  CROSSFIRE PROXY    │──── POST /api/events ────▶ Dashboard Server (:9999)
│  (stdio MITM)       │                                    │
│  • 10 rule detectors│                                    ▼
│  • Gemini AI agent  │                           React Dashboard (:5173)
│  • Chain tracker    │                           • React Flow graph
└─────────────────────┘                           • Traffic log
  │ stdin/stdout                                  • Threat detail
  ▼                                               • Guardian toggle
MCP Server
```

## Threat Detection (10 Patterns)

| Pattern | Severity | Detection |
|---------|----------|-----------|
| CRED-THEFT | critical | Sensitive file path matching (.ssh, .env, tokens) |
| SHELL-INJECT | critical | Shell command pattern matching (curl, nc, base64) |
| EXFIL-NET | high | Large payloads to reporting/telemetry tools |
| TOOL-SHADOW | medium | Unknown tool not in server's registry |
| PROMPT-RELAY | critical | Prompt injection → privileged tool calls |
| MEM-POISON | high | Suspicious writes to memory tools |
| PRIV-ESCAPE | critical | File write → shell execution chain |
| RUG-PULL | critical | SHA-256 hash diff on tool descriptions |
| TYPOSQUAT | high | Levenshtein distance to known server names |
| A2A-HIJACK | critical | A2A-specific impersonation/exfil/injection |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `CROSSFIRE_DASHBOARD_URL` | Override dashboard base URL for the proxy / A2A forwarder (default: `http://localhost:9999` or `dashboard.url` in config). |
| `CROSSFIRE_CONFIG` | Path to `crossfire.yaml` or a directory containing it; highest priority when set (useful when the MCP process cwd is not the repo). |
| `GOOGLE_API_KEY` / `CROSSFIRE_GEMINI_KEY` | Optional Gemini enrichment (install `pip install -e ".[gemini]"` first). |
| `VITE_WS_URL` | (Dashboard dev/build) Override WebSocket URL; otherwise the UI uses `ws(s)://<current-host>/ws`. |

**Gemini:** Core Crossfire works without any Google packages. Install the **`gemini`** extra and set an API key only if you want AI-assisted explanations on top of rules.

## Config-as-Code

Create `crossfire.yaml` or `.crossfire.yaml`:

```yaml
version: 1
mode: monitor  # or "block" (also toggle Guardian in the dashboard)

dashboard:
  url: "http://localhost:9999"

rules:
  sensitive_paths:
    enabled: true
    block: ["~/.ssh/*", "**/.env"]
  shell_injection:
    enabled: true
    blocked_patterns: ["curl *", "| bash"]
  typosquat:
    enabled: true
    max_distance: 2
  rug_pull:
    enabled: true
```

## Project Structure

```
crossfire/
├── proxy/              # Python MCP proxy + detectors
│   ├── __main__.py     # CLI entry point
│   ├── protocol.py     # MCP wire format handler
│   ├── proxy.py        # Bidirectional stdio proxy
│   ├── a2a_proxy.py    # A2A HTTP reverse proxy
│   ├── config.py       # YAML config loader
│   ├── installer.py    # Auto-detect & rewrite MCP configs
│   ├── scanner.py      # Active MCP vuln scan (CLI + /api/scan)
│   └── detectors/      # 10 threat detectors + Gemini AI
├── server/             # FastAPI dashboard backend
├── dashboard/          # React + React Flow frontend
├── shared/             # Event schema contract (Python + TypeScript)
├── demo/               # Poisoned weather server + sandbox
├── bin/                # Node.js CLI wrappers for npm
└── crossfire.yaml      # Default configuration
```

## Tech Stack

- **Proxy**: Python 3.10+, asyncio, aiohttp
- **Detectors**: regex, python-Levenshtein, SHA-256 hashing
- **AI Analysis**: Google ADK + Gemini 2.5 Flash
- **A2A Proxy**: FastAPI + httpx (HTTP reverse proxy)
- **Dashboard Backend**: FastAPI + WebSockets + uvicorn
- **Dashboard Frontend**: React 19, React Flow v12, Tailwind v4
- **Config**: YAML with deep merge + hot reload
- **Distribution**: pip + npm (`pip install crossfire-mcp`, `npx crossfire-mcp -- …`)

## Team

- **Yugandhar** - Python backend (proxy, server, detectors)
- **Ruthvik** - React dashboard (components, flow graph, UI)

## License

MIT
