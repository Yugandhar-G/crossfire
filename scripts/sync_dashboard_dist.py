#!/usr/bin/env python3
"""Copy built Vite output into ``server/web_dist`` for wheel packaging.

Run after:  cd dashboard && npm ci && npm run build

Usage (from repo root):  python3 scripts/sync_dashboard_dist.py
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    src = root / "dashboard" / "dist"
    dst = root / "server" / "web_dist"
    if not src.is_dir() or not any(src.iterdir()):
        print(
            "dashboard/dist is missing or empty. Build the UI first:\n"
            "  cd dashboard && npm install && npm run build",
            file=sys.stderr,
        )
        return 1
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    print(f"Synced dashboard -> {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
