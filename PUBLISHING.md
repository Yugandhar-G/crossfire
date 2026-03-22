# Publishing Crossfire

Publish **in this order**: **PyPI** (Python package **`crossfire-mcp`**) first, then **npm** (same name **`crossfire-mcp`**).  
The npm package’s `postinstall` runs `pip install crossfire-mcp` / `pipx install crossfire-mcp`, so PyPI must already have that version.

> **Why not `crossfire` on PyPI?** The project name `crossfire` is already taken by another package. This repo publishes as **`crossfire-mcp`**. CLI commands are still **`crossfire`** and **`crossfire-proxy`** after install.

## 1. One-time accounts

| Registry | URL | What you need |
|----------|-----|----------------|
| **PyPI** | https://pypi.org | Account + [API token](https://pypi.org/manage/account/token/) (scope: entire account or project `crossfire-mcp`) |
| **TestPyPI** (optional) | https://test.pypi.org | Separate token for dry runs |
| **npm** | https://www.npmjs.com | Account, `npm login`, 2FA enabled for publishing |

## 2. Build the Python artifacts (from repo root)

Always bundle the built dashboard into the wheel:

```bash
cd dashboard && npm ci && npm run build && cd ..
python3 scripts/sync_dashboard_dist.py
python3 -m pip install --upgrade build twine
rm -rf dist/*.whl dist/*.tar.gz   # optional: avoid uploading old `crossfire-*` builds
python3 -m build
```

Check `dist/` (names use underscores in the filename):

- `crossfire_mcp-0.1.0-py3-none-any.whl`
- `crossfire_mcp-0.1.0.tar.gz`

Optional smoke test in a clean venv:

```bash
python3 -m venv /tmp/cf-test && /tmp/cf-test/bin/pip install dist/crossfire_mcp-0.1.0-py3-none-any.whl
/tmp/cf-test/bin/crossfire doctor
```

## 3. Publish to PyPI

### TestPyPI (recommended first upload)

```bash
python3 -m twine upload --repository testpypi dist/crossfire_mcp-*
```

Install from TestPyPI:

```bash
pip install -i https://test.pypi.org/simple/ crossfire-mcp==0.1.0
```

### Production PyPI

```bash
python3 -m twine upload dist/crossfire_mcp-*
```

Uses `~/.pypirc` or env vars `TWINE_USERNAME=__token__` and `TWINE_PASSWORD=pypi-...`.

## 4. Publish to npm

From repo root (after PyPI has the same version):

```bash
npm whoami   # must show your npm user
npm publish --access public
```

`crossfire-mcp` is an **unscoped** name; `--access public` is required for free accounts on the first publish.

Dry run (no upload):

```bash
npm pack
```

## 5. Version bumps (next release)

Bump **both** to the same logical version:

1. `pyproject.toml` → `[project] version`
2. `package.json` → `"version"`

Then repeat sections 2–4. The npm `postinstall` installs `crossfire-mcp==<package.json version>` when possible.

## 6. What end users run

After both are published:

```bash
pip install crossfire-mcp
# or (note `--` so subcommands go to Crossfire, not npx):
npx --yes crossfire-mcp@0.1.0 -- dashboard
```

If `npx crossfire-mcp doctor` fails with `command not found`, use `npx --yes crossfire-mcp@0.1.0 -- doctor` or `pip install crossfire-mcp` then `crossfire doctor`.

## 7. Troubleshooting

| Issue | What to check |
|-------|----------------|
| Wheel missing UI | Run `sync_dashboard_dist.py` before `python -m build`; confirm `server/web_dist/` has `index.html` |
| `twine upload` 403 “isn't allowed to upload to project `crossfire`” | You were uploading the old **`crossfire`** wheel; rebuild after renaming to **`crossfire-mcp`** in `pyproject.toml`, then upload **`crossfire_mcp-*`** only |
| `twine upload` 403 (other) | Token scope, or wrong PyPI user |
| `npm publish` E403 | Not logged in, wrong package name, or need `--access public` |
| `npx` postinstall fails | PyPI does not have **`crossfire-mcp`** at that version yet — publish Python first |
