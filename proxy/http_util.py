"""Shared lightweight HTTP helpers (stdlib only, no async deps)."""

import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def http_get_json(url: str, timeout: float = 3.0, quiet: bool = False) -> dict | None:
    """GET JSON from *url*. Returns parsed dict or None on any failure."""
    try:
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, HTTPError, OSError, json.JSONDecodeError) as exc:
        if not quiet:
            sys.stderr.write(f"[crossfire] Request failed ({url}): {exc}\n")
        return None


def http_post_json(url: str, body: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """POST JSON; returns (ok, message)."""
    try:
        data = json.dumps(body).encode("utf-8")
        req = Request(
            url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return False, f"HTTP {getattr(resp, 'status', '?')}"
            return True, "ok"
    except HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except (URLError, OSError, TypeError, ValueError) as exc:
        return False, str(exc)
