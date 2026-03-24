#!/usr/bin/env node
/**
 * postinstall: bootstrap the Python crossfire-mcp package.
 *
 * - Git clone / dev (pyproject.toml present): pip install -e . into .venv
 * - npm consumer (no pyproject.toml): pip install crossfire-mcp from PyPI
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const packageDir = path.resolve(__dirname, '..');
const isWin = process.platform === 'win32';
const pyproject = path.join(packageDir, 'pyproject.toml');

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
    '[crossfire-mcp] Python 3.10+ not found.\n' +
      '  Install Python, then run: pip install crossfire-mcp\n'
  );
  return null;
}

function checkPythonVersion(pyParts) {
  try {
    const version = execSync(`${pyParts.join(' ')} --version`, { encoding: 'utf-8' }).trim();
    const match = version.match(/(\d+)\.(\d+)/);
    if (match && (parseInt(match[1], 10) < 3 || (parseInt(match[1], 10) === 3 && parseInt(match[2], 10) < 10))) {
      console.warn(`[crossfire-mcp] Python 3.10+ required. Found: ${version}`);
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function installEditableDev(pyParts) {
  const venvDir = path.join(packageDir, '.venv');
  const pip = isWin
    ? path.join(venvDir, 'Scripts', 'pip3.exe')
    : path.join(venvDir, 'bin', 'pip3');

  if (!fs.existsSync(pip)) {
    console.log('[crossfire-mcp] Creating .venv ...');
    try {
      execSync(`${pyParts.join(' ')} -m venv "${venvDir}"`, { cwd: packageDir, stdio: 'inherit' });
    } catch {
      console.warn('[crossfire-mcp] Could not create .venv. Run: python3 -m venv .venv && pip install -e .');
      return;
    }
  }

  try {
    execSync(`"${pip}" install -e ".[gemini]"`, { cwd: packageDir, stdio: 'inherit', shell: true });
  } catch {
    try {
      execSync(`"${pip}" install -e .`, { cwd: packageDir, stdio: 'inherit', shell: true });
      console.log('[crossfire-mcp] Installed core. For Gemini: .venv/bin/pip3 install -e ".[gemini]"');
    } catch {
      console.warn('[crossfire-mcp] pip install -e . failed. Run manually from repo root.');
    }
  }
}

function installFromPyPI(pyParts) {
  console.log('[crossfire-mcp] Installing Python package from PyPI ...');
  try {
    execSync(`${pyParts.join(' ')} -m pip install crossfire-mcp`, { stdio: 'inherit' });
    console.log('[crossfire-mcp] Python package installed. Run: crossfire start');
  } catch {
    console.warn(
      '[crossfire-mcp] Could not install Python package.\n' +
        '  Run manually: pip install crossfire-mcp\n'
    );
  }
}

function main() {
  const pyParts = resolvePython();
  if (!pyParts) return;
  if (!checkPythonVersion(pyParts)) return;

  if (fs.existsSync(pyproject)) {
    console.log('[crossfire-mcp] Dev layout detected. Installing editable into .venv ...');
    installEditableDev(pyParts);
  } else {
    installFromPyPI(pyParts);
  }
}

try {
  main();
} catch (err) {
  console.warn('[crossfire-mcp] postinstall error:', err && err.message ? err.message : err);
}
process.exit(0);
