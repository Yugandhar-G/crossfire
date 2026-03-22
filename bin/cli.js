#!/usr/bin/env node
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

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
  console.error('Crossfire requires Python 3.10+. No suitable interpreter found in PATH.');
  process.exit(1);
}

function checkPythonVersion(pyParts) {
  try {
    const version = execSync(`${pyParts.join(' ')} --version`, { encoding: 'utf-8' }).trim();
    const match = version.match(/(\d+)\.(\d+)/);
    if (
      match &&
      (parseInt(match[1], 10) < 3 || (parseInt(match[1], 10) === 3 && parseInt(match[2], 10) < 10))
    ) {
      console.error(`Crossfire requires Python 3.10+. Found: ${version}`);
      process.exit(1);
    }
  } catch {
    console.error('Crossfire requires Python 3.10+. Could not read Python version.');
    process.exit(1);
  }
}

function thisCliPath() {
  return fs.realpathSync(path.join(__dirname, 'cli.js'));
}

/** Every `crossfire` on PATH (npm global, pip --user, pipx, venv, …). */
function allCrossfireBins() {
  const bins = [];
  if (process.platform === 'win32') {
    try {
      const out = execSync('where crossfire', { encoding: 'utf-8', shell: true });
      for (const line of out.split(/\r?\n/)) {
        const t = line.trim();
        if (t) bins.push(t);
      }
    } catch {
      /* none */
    }
  } else {
    try {
      const out = execSync('which -a crossfire 2>/dev/null', { encoding: 'utf-8', shell: true });
      for (const line of out.split('\n')) {
        const t = line.trim();
        if (t) bins.push(t);
      }
    } catch {
      /* none */
    }
  }
  return bins;
}

/**
 * Prefer the real Python console script. The npm package also installs a `crossfire`
 * bin pointing at this file; if that appears first on PATH, `spawn('crossfire')`
 * would recurse or mis-resolve. Skip any `crossfire` that is this same `cli.js`.
 */
function findPythonCrossfireBin() {
  const self = thisCliPath();
  for (const bin of allCrossfireBins()) {
    try {
      if (fs.realpathSync(bin) !== self) return bin;
    } catch {
      continue;
    }
  }
  return null;
}

function spawnCrossfire(binary, args) {
  const child = spawn(binary, args, {
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env: process.env,
  });
  child.on('exit', (code) => process.exit(code ?? 0));
  child.on('error', (err) => {
    console.error(`Failed to start crossfire: ${err.message}`);
    process.exit(1);
  });
}

function canImportProxy(pyParts) {
  try {
    execSync(`${pyParts.join(' ')} -c "import proxy"`, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function spawnPythonModuleProxy(pyParts, args) {
  const child = spawn(pyParts[0], [...pyParts.slice(1), '-m', 'proxy', ...args], {
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env: process.env,
  });
  child.on('exit', (code) => process.exit(code ?? 0));
  child.on('error', (err) => {
    console.error(`Failed to start Crossfire: ${err.message}`);
    process.exit(1);
  });
}

let args = process.argv.slice(2);
if (args.length === 0) {
  args = ['start'];
}

const packageDir = path.resolve(__dirname, '..');
const pyproject = path.join(packageDir, 'pyproject.toml');

const pythonCrossfire = findPythonCrossfireBin();
if (pythonCrossfire) {
  spawnCrossfire(pythonCrossfire, args);
} else if (fs.existsSync(pyproject)) {
  const pyParts = resolvePython();
  checkPythonVersion(pyParts);
  const child = spawn(pyParts[0], [...pyParts.slice(1), '-m', 'proxy', ...args], {
    cwd: packageDir,
    stdio: 'inherit',
    env: { ...process.env, PYTHONPATH: packageDir },
  });
  child.on('exit', (code) => process.exit(code ?? 0));
  child.on('error', (err) => {
    console.error(`Failed to start Crossfire: ${err.message}`);
    process.exit(1);
  });
} else {
  const pyParts = resolvePython();
  checkPythonVersion(pyParts);
  if (canImportProxy(pyParts)) {
    spawnPythonModuleProxy(pyParts, args);
  } else {
    console.error(
      'Crossfire Python tools are not installed, or `crossfire` on PATH is only the npm shim.\n' +
        'Install from PyPI, then retry:\n' +
        '  pip install crossfire-mcp\n' +
        '  # or: pipx install crossfire-mcp\n' +
        'Ensure `~/.local/bin` (pip --user) or your pipx bin dir is on PATH before the npm global bin.'
    );
    process.exit(1);
  }
}
