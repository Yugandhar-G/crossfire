#!/usr/bin/env node
const { execSync, spawn } = require('child_process');
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
  process.stderr.write('Crossfire requires Python 3.10+. No suitable interpreter found in PATH.\n');
  process.exit(1);
}

function crossfireProxyOnPath() {
  try {
    if (process.platform === 'win32') {
      execSync('where crossfire-proxy', { stdio: 'pipe', shell: true });
    } else {
      execSync('command -v crossfire-proxy', { stdio: 'pipe', shell: true });
    }
    return true;
  } catch {
    return false;
  }
}

const args = process.argv.slice(2);
const packageDir = path.resolve(__dirname, '..');

if (crossfireProxyOnPath()) {
  const child = spawn('crossfire-proxy', args, {
    stdio: ['pipe', 'pipe', 'inherit'],
    shell: process.platform === 'win32',
    env: process.env,
  });
  process.stdin.pipe(child.stdin);
  child.stdout.pipe(process.stdout);
  child.on('exit', (code) => process.exit(code ?? 0));
  child.on('error', (err) => {
    process.stderr.write(`Crossfire proxy error: ${err.message}\n`);
    process.exit(1);
  });
} else {
  const pyParts = resolvePython();
  const child = spawn(pyParts[0], [...pyParts.slice(1), '-m', 'proxy', 'proxy', ...args], {
    cwd: packageDir,
    stdio: ['pipe', 'pipe', 'inherit'],
    env: { ...process.env, PYTHONPATH: packageDir },
  });
  process.stdin.pipe(child.stdin);
  child.stdout.pipe(process.stdout);
  child.on('exit', (code) => process.exit(code ?? 0));
  child.on('error', (err) => {
    process.stderr.write(`Crossfire proxy error: ${err.message}\n`);
    process.exit(1);
  });
}
