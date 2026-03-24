"""MCP stdio protocol handler -- newline-delimited JSON-RPC 2.0.

Security hardening:
 - Maximum message size enforcement (10MB default) prevents OOM
 - Read timeout prevents hanging on malicious slow clients
 - Proper error propagation for dropped messages
"""

import asyncio
import json
import sys
from typing import Literal


MessageType = Literal["request", "notification", "response", "unknown"]

MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB
READ_TIMEOUT_SECONDS = 300  # 5 minutes


def classify_message(msg: dict) -> MessageType:
    if "method" in msg and "id" in msg:
        return "request"
    if "method" in msg and "id" not in msg:
        return "notification"
    if "id" in msg and ("result" in msg or "error" in msg):
        return "response"
    return "unknown"


async def read_message(reader: asyncio.StreamReader) -> dict | None:
    """Read a single newline-delimited JSON-RPC message from a stream.

    Enforces MAX_MESSAGE_SIZE to prevent memory exhaustion and
    READ_TIMEOUT_SECONDS to prevent hanging on stalled connections.
    """
    try:
        try:
            line = await asyncio.wait_for(
                reader.readline(),
                timeout=READ_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            sys.stderr.write(
                f"[crossfire] Read timeout after {READ_TIMEOUT_SECONDS}s\n"
            )
            return None

        if not line:
            return None

        if len(line) > MAX_MESSAGE_SIZE:
            sys.stderr.write(
                f"[crossfire] Message too large ({len(line)} bytes, max {MAX_MESSAGE_SIZE}). Dropped.\n"
            )
            return None

        decoded = line.decode("utf-8").strip()
        if not decoded:
            return None
        return json.loads(decoded)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        sys.stderr.write(f"[crossfire] Protocol error: {exc}\n")
        return None
    except Exception as exc:
        sys.stderr.write(f"[crossfire] Unexpected protocol error: {exc}\n")
        return None


def write_message(writer, msg: dict) -> None:
    """Write a single newline-delimited JSON-RPC message to a stream.

    Works with both asyncio.StreamWriter and synchronous stdout.
    """
    data = json.dumps(msg, separators=(",", ":")) + "\n"
    encoded = data.encode("utf-8")
    if isinstance(writer, asyncio.StreamWriter):
        writer.write(encoded)
    else:
        writer.buffer.write(encoded)
        writer.flush()


async def drain_writer(writer) -> None:
    """Drain an asyncio StreamWriter, no-op for synchronous writers."""
    if isinstance(writer, asyncio.StreamWriter):
        await writer.drain()


async def create_stdin_reader() -> asyncio.StreamReader:
    """Create an asyncio StreamReader connected to the process stdin."""
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    return reader
