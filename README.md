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

## Usage

```bash
crossfire install      # rewrite MCP configs to route through the proxy
crossfire dashboard    # API + static UI
```

Open `http://localhost:9999`. Smoke-test without MCP: `crossfire ping` (add `--threat` for a sample critical event).

Diagnostics: `crossfire doctor`.

## Configuration

- **`crossfire.yaml`** or **`.crossfire.yaml`** in the project (see repo root for an example).
- **`CROSSFIRE_CONFIG`** — absolute path to config when the MCP process cwd is not the repo.
- **`CROSSFIRE_DASHBOARD_URL`** — dashboard base URL if not on localhost:9999.
- **`GOOGLE_API_KEY`** or **`CROSSFIRE_GEMINI_KEY`** — optional; requires the `gemini` extra.

The stdio proxy applies to MCP servers launched with a **`command`** in config. URL-only MCP entries are not proxied.

## npm / npx

The `crossfire-mcp` package on npm runs `postinstall` to install the Python CLI from PyPI. From a git clone with `pyproject.toml` present, postinstall uses editable `pip install -e .` instead.

```bash
npx --yes crossfire-mcp@latest -- dashboard
```

## Publishing

See **[PUBLISHING.md](PUBLISHING.md)** for wheels, syncing the dashboard into the package, and PyPI/npm release steps.

## License

MIT — see [LICENSE](LICENSE).
