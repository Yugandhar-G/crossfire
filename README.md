# Crossfire

Transparent MCP and A2A proxy with real-time threat detection and a local dashboard.

**Repository:** [github.com/Yugandhar-G/crossfire](https://github.com/Yugandhar-G/crossfire)

## Requirements

- Python 3.10+
- Node 18+ (only to build the dashboard UI from this repo)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Optional Gemini-assisted analysis:

```bash
pip install -e ".[gemini]"
```

Build the dashboard once so the server can serve the full UI (default `http://localhost:9999`):

```bash
cd dashboard && npm ci && npm run build && cd ..
```

### `pip install crossfire-mcp` (PyPI)

The published **wheel** installs only the runtime:

| Shipped | Purpose |
|--------|---------|
| **`proxy/`** | MCP/A2A proxy, CLI, detectors, installer |
| **`server/`** | Dashboard API (FastAPI) + bundled **`web_dist/`** UI when you build before release |
| **`shared/`** | Event schema (Python) |

Console scripts: **`crossfire`**, **`crossfire-proxy`**.

**Not** included in the wheel or PyPI sdist: **`tests/`**, **`demo/`**, **`dashboard/`** source, or other repo-only files. (Runtime Python remains readable in `site-packages`, like any interpreter package.)

## Usage

```bash
crossfire install      # rewrite MCP configs to route through the proxy
crossfire dashboard    # API + static UI
```

Open `http://localhost:9999`. Smoke-test without MCP: `crossfire ping` (add `--threat` for a sample critical event).

Diagnostics: `crossfire doctor`.

## Configuration

Crossfire loads **`crossfire.yaml`** (or **`.crossfire.yaml`**) from the first location found:

1. `CROSSFIRE_CONFIG` env var (absolute path to file or directory)
2. Current working directory
3. Package / repo root
4. `~/.crossfire.yaml`

Every key has a built-in default, so the file is optional — an empty YAML is valid. User values are deep-merged over defaults; you only need to specify what you want to override.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `CROSSFIRE_CONFIG` | Absolute path to config file or directory containing one |
| `CROSSFIRE_DASHBOARD_URL` | Dashboard base URL (overrides `dashboard.url` in YAML) |
| `CROSSFIRE_HMAC_SECRET` | HMAC signing secret (overrides `hmac.secret` in YAML) |
| `GOOGLE_API_KEY` or `CROSSFIRE_GEMINI_KEY` | Gemini API key; requires the `gemini` extra |

### Full config reference

```yaml
version: 1

# Guardian mode at startup: "monitor" (observe) or "block" (deny critical/high threats)
mode: monitor

dashboard:
  url: "http://localhost:9999"

# ─── Threat Detection Rules ───────────────────────────────────────────
rules:

  # Block access to sensitive file paths (globs)
  sensitive_paths:
    enabled: true
    severity: critical        # severity assigned when triggered
    allow: []                 # path globs that bypass the check
    block:
      - "~/.ssh/*"
      - "~/.aws/*"
      - "**/.env"
      - "**/.env.*"
      - "**/credentials*"
      - "**/private_key*"
      - "**/*.pem"
      - "**/*.key"

  # Detect shell injection in tool arguments
  shell_injection:
    enabled: true
    severity: critical
    allowed_commands: []      # shell commands permitted even if they match patterns
    blocked_patterns:
      - "curl *"
      - "wget *"
      - "nc *"
      - "| bash"
      - "| sh"
      - "> /dev/tcp"
      - "base64"
      - "rm -rf"

  # Detect Levenshtein-close server names vs known legitimate ones
  typosquat:
    enabled: true
    known_servers:             # add your org's real server names here
      - filesystem
      - github
      - gitlab
      - slack
      - postgres
      - mysql
      - redis
      - mongodb
      - memory
      - brave-search
      - puppeteer
      - docker
    max_distance: 2            # Levenshtein edit-distance threshold

  # Detect tool-definition changes between successive tools/list calls
  rug_pull:
    enabled: true
    severity: critical

  # Flag large payloads sent to "reporting" tools
  exfiltration:
    enabled: true
    max_payload_bytes: 500
    monitored_tools:           # tool-name globs
      - "*telemetry*"
      - "*report*"
      - "*analytics*"
      - "*send*"
      - "*track*"

  # Flag prompt injection in tool descriptions
  prompt_injection:
    enabled: true
    max_description_length: 2000   # descriptions longer than this are suspicious

  # Remaining detectors — each can be disabled with `enabled: false`
  memory_poisoning:        { enabled: true }
  prompt_relay:            { enabled: true }
  privilege_escalation:    { enabled: true }
  unknown_tool:            { enabled: true }
  schema_poisoning:        { enabled: true }
  path_traversal:          { enabled: true }
  token_passthrough:       { enabled: true }
  sql_injection:           { enabled: true }
  resource_poisoning:      { enabled: true }
  oauth_deputy:            { enabled: true }
  config_poisoning:        { enabled: true }
  session_flaws:           { enabled: true }
  cross_tenant:            { enabled: true }
  neighborjack:            { enabled: true }

  # Optional Gemini LLM-powered secondary analysis
  gemini_analysis:
    enabled: true
    model: gemini-2.5-flash
    confidence_threshold: 0.7  # threats below this confidence are discarded

# ─── Policy Engine ────────────────────────────────────────────────────
# Fine-grained per-server/per-tool allow/block rules.
# Rules evaluate in order; first match wins. Glob patterns supported.
policy:
  default_action: allow        # "allow" or "block" when no rule matches

  rules:                       # ordered list — first match wins
    # Example: block all shell-related tools on untrusted servers
    # - server: "untrusted-*"
    #   tool: "run_command"
    #   action: block
    #   reason: "Shell access denied on untrusted servers"
    #
    # Example: block only when severity is high or above
    # - server: "*"
    #   tool: "*"
    #   action: block
    #   severity_threshold: high
    #   reason: "Block high+ severity threats"
    []

  # Per-server tool blocklists (tool calls to these are denied)
  blocked_tools: {}
    # Example:
    # my-server:
    #   - dangerous_tool
    #   - run_shell

  # Per-server tool allowlists (only these tools are permitted; all others blocked)
  allowed_tools: {}
    # Example:
    # production-server:
    #   - read_file
    #   - list_files

# ─── Server Trust ─────────────────────────────────────────────────────
servers:
  trusted: []                  # server names that skip certain checks
  untrusted: []                # server names flagged for extra scrutiny

# ─── A2A (Agent-to-Agent) Proxy ──────────────────────────────────────
a2a:
  enabled: true
  listen_port: 9998
  upstream_agents: []          # upstream agent base URLs to proxy

# ─── MCP HTTP Proxy ──────────────────────────────────────────────────
mcp_http_proxy:
  tool_hiding: true            # hide blocked tools from tools/list responses
  default_port: 8888           # port for the HTTP proxy server

# ─── Audit Log ────────────────────────────────────────────────────────
# Append-only JSONL audit trail with rotation and automatic secret redaction.
audit:
  enabled: true
  path: "./crossfire-audit.jsonl"
  max_size_mb: 100             # rotate when log exceeds this size

# ─── HMAC Event Signing ──────────────────────────────────────────────
# Signs proxy→dashboard events with HMAC-SHA256 to prevent injection/tampering.
# Also settable via CROSSFIRE_HMAC_SECRET env var.
hmac:
  secret: ""                   # empty = signing disabled
```

### Config resolution

The stdio proxy applies to MCP servers launched with a **`command`** in config. URL-only MCP entries are not proxied. When the MCP server subprocess has a different working directory, the config loader also checks the package/repo root so `crossfire.yaml` is still found.

### Quick examples

Disable a specific detector:

```yaml
rules:
  sql_injection:
    enabled: false
```

Block a tool on a specific server:

```yaml
policy:
  blocked_tools:
    my-server:
      - run_shell
      - execute_command
```

Only allow specific tools on a production server:

```yaml
policy:
  allowed_tools:
    prod-db:
      - read_query
      - list_tables
```

Block all calls with high+ severity across the board:

```yaml
policy:
  rules:
    - server: "*"
      tool: "*"
      action: block
      severity_threshold: high
      reason: "Block high-severity threats globally"
```

Add custom sensitive paths:

```yaml
rules:
  sensitive_paths:
    block:
      - "~/.ssh/*"
      - "~/.aws/*"
      - "**/secrets.yaml"
      - "**/internal/keys/**"
```

Enable audit with a custom path:

```yaml
audit:
  enabled: true
  path: "/var/log/crossfire/audit.jsonl"
  max_size_mb: 500
```

Enable HMAC signing:

```yaml
hmac:
  secret: "your-secret-here"
```

## npm / npx

The npm package is a thin wrapper: **`postinstall`** runs **`pip`** / **`pipx`** to install **`crossfire-mcp` from [PyPI](https://pypi.org/project/crossfire-mcp/)** (Python 3.10+ on `PATH`). In a git clone, `postinstall` uses **`pip install -e .`** when `pyproject.toml` is present.

**There is no `npx install …` — use one of:**

```bash
npm install -g crossfire-mcp
crossfire doctor
```

```bash
npx --yes crossfire-mcp@latest -- doctor
```

```bash
npx --yes crossfire-mcp@latest -- dashboard
```

If **`postinstall`** warns or the `crossfire` command is missing, run **`pip install crossfire-mcp`** or **`pipx install crossfire-mcp`**, then ensure **`~/.local/bin`** (pip `--user`) or your pipx bin directory is on **`PATH`**. The npm shim also falls back to **`python3 -m proxy …`** when the package is installed but the **`crossfire`** script is not on **`PATH`** (common with **conda** or **`npx`** PATH ordering).

**Releases:** publish the **`crossfire-mcp`** wheel to PyPI (`python -m build`, `twine upload dist/*`) and keep **`package.json`** / **`pyproject.toml`** versions in sync with **`npm publish`**.

## License

MIT — see [LICENSE](LICENSE).
