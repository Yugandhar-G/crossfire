#!/usr/bin/env node
/**
 * postinstall: ensure the Python `crossfire-mcp` package is available.
 *
 * - Git clone / dev: pyproject.toml next to this file → pip install -e .
 * - Published npm package: install from PyPI via pipx (preferred) or pip --user
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const packageDir = path.resolve(__dirname, '..');
const isWin = process.platform === 'win32';
const pyproject = path.join(packageDir, 'pyproject.toml');

function readPkgVersion() {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf8'));
    return j.version || '0.1.0';
  } catch {
    return '0.1.0';
  }
}

function resolvePython() {
  const candidates =
    process.platform === 'win32'
      ? [['py', '-3'], ['py'], ['python'], ['python3']]
      : [['python3'], ['python'], ['py', '-3']];
  for (const parts of candidates) {
    try {
      execSync(`${parts.join(' ')} --version`, { stdio: 'pipe' });
      return parts;
    } catch {
      /* try next */
    }
  }
  console.warn(
    '[crossfire-mcp] Python 3.10+ not found. Install Python, then run: pip install crossfire-mcp\n'
  );
  return null;
}

function crossfireOnPath() {
  try {
    if (isWin) {
      execSync('where crossfire', { stdio: 'pipe', shell: true });
    } else {
      execSync('command -v crossfire', { stdio: 'pipe', shell: true });
    }
    return true;
  } catch {
    return false;
  }
}

function pipShowCrossfire(pyParts) {
  try {
    const out = execSync(`${pyParts.join(' ')} -m pip show crossfire-mcp`, {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const m = out.match(/^Version:\s*(.+)$/m);
    return m ? m[1].trim() : null;
  } catch {
    return null;
  }
}

function installEditableDev(pyParts) {
  const venvDir = path.join(packageDir, '.venv');
  const pip = isWin
    ? path.join(venvDir, 'Scripts', 'pip3.exe')
    : path.join(venvDir, 'bin', 'pip3');

  if (!fs.existsSync(pip)) {
    console.log('[crossfire-mcp] Creating .venv for Python package (dev mode)...');
    try {
      execSync(`${pyParts.join(' ')} -m venv "${venvDir}"`, { cwd: packageDir, stdio: 'inherit' });
    } catch {
      console.warn(
        '[crossfire-mcp] Could not create .venv. Run: python3 -m venv .venv && .venv/bin/pip3 install -e .'
      );
      return;
    }
  }

  try {
    execSync(`"${pip}" install -e ".[gemini]"`, {
      cwd: packageDir,
      stdio: 'inherit',
      shell: true,
    });
  } catch {
    try {
      execSync(`"${pip}" install -e .`, { cwd: packageDir, stdio: 'inherit', shell: true });
      console.log('[crossfire-mcp] Installed core only. For Gemini: .venv/bin/pip3 install -e ".[gemini]"');
    } catch {
      console.warn('[crossfire-mcp] Could not pip install -e . Run manually from repo root.');
    }
  }
}

function installFromPyPI(pyParts, pkgVersion) {
  const specPinned = `crossfire-mcp==${pkgVersion}`;
  const py = pyParts.join(' ');

  // Prefer latest PyPI release without pinning first. npm and PyPI versions are not
  // always published in lockstep (e.g. npm 0.1.1 while PyPI is still 0.1.0).
  try {
    execSync('pipx --version', { stdio: 'pipe' });
    try {
      execSync('pipx install crossfire-mcp', { stdio: 'inherit', shell: true });
      return true;
    } catch {
      try {
        execSync('pipx upgrade crossfire-mcp', { stdio: 'inherit', shell: true });
        return true;
      } catch {
        /* fall through to pip */
      }
    }
  } catch {
    /* pipx not available */
  }

  try {
    execSync(`${py} -m pip install --user crossfire-mcp`, {
      stdio: 'inherit',
      shell: true,
    });
    return true;
  } catch {
    /* try exact pin last (fails if that wheel was never uploaded) */
  }

  try {
    execSync('pipx --version', { stdio: 'pipe' });
    execSync(`pipx install ${specPinned}`, { stdio: 'inherit', shell: true });
    return true;
  } catch {
    /* last pip attempt */
  }

  try {
    execSync(`${py} -m pip install --user ${specPinned}`, {
      stdio: 'inherit',
      shell: true,
    });
    return true;
  } catch {
    console.warn(
      '[crossfire-mcp] Could not install crossfire-mcp from PyPI. Install manually:\n' +
        '  pip install crossfire-mcp\n' +
        '  # or: pipx install crossfire-mcp\n'
    );
    return false;
  }
}

function main() {
  const pyParts = resolvePython();
  if (!pyParts) {
    return;
  }

  if (fs.existsSync(pyproject)) {
    console.log('[crossfire-mcp] Development layout detected (pyproject.toml). Installing editable...');
    installEditableDev(pyParts);
    return;
  }

  const want = readPkgVersion();
  if (crossfireOnPath()) {
    const v = pipShowCrossfire(pyParts);
    if (v) {
      console.log(`[crossfire-mcp] crossfire ${v} already on PATH.`);
      return;
    }
  }

  console.log('[crossfire-mcp] Installing Python package crossfire-mcp from PyPI...');
  installFromPyPI(pyParts, want);
}

try {
  main();
} catch (err) {
  console.warn('[crossfire-mcp] postinstall error:', err && err.message ? err.message : err);
  console.warn(
    '[crossfire-mcp] Install the Python CLI manually, then ensure it is on PATH:\n' +
      '  pip install crossfire-mcp\n' +
      '  # or: pipx install crossfire-mcp\n'
  );
}
// Do not fail `npm install` / `npx` if pip is externally managed or PyPI is unreachable.
process.exit(0);
