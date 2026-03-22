"""Tests for MCP newline-delimited JSON-RPC helpers."""

import asyncio
import json

import pytest

from proxy.protocol import classify_message, read_message


def test_classify_message_request() -> None:
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    assert classify_message(msg) == "request"


def test_classify_message_notification() -> None:
    msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert classify_message(msg) == "notification"


def test_classify_message_response() -> None:
    msg = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
    assert classify_message(msg) == "response"


def test_classify_message_response_error() -> None:
    msg = {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}}
    assert classify_message(msg) == "response"


def test_classify_message_unknown() -> None:
    assert classify_message({}) == "unknown"


@pytest.mark.asyncio
async def test_read_message_valid_json() -> None:
    reader = asyncio.StreamReader()
    line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n"
    reader.feed_data(line.encode("utf-8"))
    reader.feed_eof()
    msg = await read_message(reader)
    assert msg is not None
    assert msg["method"] == "ping"


@pytest.mark.asyncio
async def test_read_message_eof_returns_none() -> None:
    reader = asyncio.StreamReader()
    reader.feed_eof()
    assert await read_message(reader) is None


@pytest.mark.asyncio
async def test_read_message_invalid_json_returns_none() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"not-json\n")
    reader.feed_eof()
    assert await read_message(reader) is None
