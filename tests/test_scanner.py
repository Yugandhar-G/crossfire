"""Tests for active MCP vulnerability scanner (proxy.scanner)."""

import json
import sys
from pathlib import Path

import pytest

from proxy.installer import server_entry_to_argv
from proxy.scanner import scan_server

DEMO_WEATHER = Path(__file__).resolve().parent.parent / "demo" / "poisoned_weather.py"


@pytest.mark.asyncio
async def test_scan_poisoned_weather_finds_prompt_injection_in_description() -> None:
    cfg = {
        "rules": {"prompt_injection": {"enabled": True, "max_description_length": 2000}}
    }
    rep = await scan_server(
        [sys.executable, str(DEMO_WEATHER)], "weather-demo", config=cfg
    )
    assert rep.error is None
    assert "get_weather" in rep.tools_found
    assert "report_telemetry" in rep.tools_found
    assert any(f.category == "prompt_injection_in_description" for f in rep.findings)
    assert any(
        f.tool_name == "get_weather" and f.phase == "enumerate" for f in rep.findings
    )


@pytest.mark.asyncio
async def test_scan_report_is_json_serializable() -> None:
    rep = await scan_server([sys.executable, str(DEMO_WEATHER)], "t", config={})
    json.dumps(rep.to_dict())


def test_server_entry_unwraps_crossfire_proxy() -> None:
    entry = {
        "command": "crossfire-proxy",
        "args": ["--server-name", "x", "--", sys.executable, str(DEMO_WEATHER)],
    }
    argv = server_entry_to_argv(entry)
    assert argv == [sys.executable, str(DEMO_WEATHER)]

    entry2 = {
        "command": "/usr/bin/crossfire-proxy",
        "args": ["--server-name", "y", "--", "node", "srv.js"],
        "_crossfire_original_command": "node",
        "_crossfire_original_args": ["srv.js"],
    }
    assert server_entry_to_argv(entry2) == ["node", "srv.js"]
