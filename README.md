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

- **`crossfire.yaml`** or **`.crossfire.yaml`** in the project (see repo root for an example).
- **`CROSSFIRE_CONFIG`** — absolute path to config when the MCP process cwd is not the repo.
- **`CROSSFIRE_DASHBOARD_URL`** — dashboard base URL if not on localhost:9999.
- **`GOOGLE_API_KEY`** or **`CROSSFIRE_GEMINI_KEY`** — optional; requires the `gemini` extra.

The stdio proxy applies to MCP servers launched with a **`command`** in config. URL-only MCP entries are not proxied.

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
