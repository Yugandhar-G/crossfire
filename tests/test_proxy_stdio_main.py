"""Tests for ``crossfire-proxy`` pip console entry."""

import sys

import pytest


def test_proxy_stdio_main_invokes_run_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[list[str], str, str]] = []

    async def fake_run_proxy(
        server_cmd: list[str], server_name: str, source: str = "ide"
    ) -> None:
        captured.append((server_cmd, server_name, source))

    monkeypatch.setattr("proxy.proxy.run_proxy", fake_run_proxy)
    monkeypatch.setattr(
        sys,
        "argv",
        ["crossfire-proxy", "--server-name", "figma", "--", "/usr/bin/echo", "hi"],
    )
    from proxy.proxy_stdio_main import main

    main()
    assert len(captured) == 1
    assert captured[0][1] == "figma"
    assert captured[0][0] == ["/usr/bin/echo", "hi"]
    assert captured[0][2] == "ide"
