"""Gemini-powered threat analysis using Google ADK.

Provides LLM-based secondary analysis for every flagged threat, covering
all 28 known MCP/A2A attack patterns.  Includes a rolling context buffer
so the model can detect multi-step attack chains (e.g. file read -> exfil).
"""

import asyncio
import json
import os
import sys
from collections import deque

GEMINI_TIMEOUT_SECONDS = 8

GEMINI_PROMPT = """You are an MCP/A2A security analyst for the Crossfire proxy.

Analyze this tool call sequence and determine if it represents an attack.

Recent tool calls (chronological):
{context}

Current tool call being evaluated:
{current}

Regex-based detectors already flagged these patterns:
{flagged}

Known MCP/A2A attack patterns (full list):
 1. EXFIL-NET        – File read followed by network send (data exfiltration)
 2. CRED-THEFT       – Reading credential files (.ssh, .env, tokens)
 3. SHELL-INJECT     – Command/shell injection via unsanitized input
 4. MEM-POISON       – Writing malicious context to memory/notes tools
 5. PROMPT-RELAY     – Untrusted content triggering privileged tool calls
 6. PRIV-ESCAPE      – File write followed by shell execution
 7. RUG-PULL         – Tool description changed after initial trust
 8. TYPOSQUAT        – Server name similar to known legitimate server
 9. TOOL-SHADOW      – Cross-server tool name collision / shadowing
10. SCHEMA-POISON    – Injection hidden in inputSchema or annotations fields
11. PATH-TRAVERSE    – Path traversal (../) or symlink bypass to escape sandbox
12. TOKEN-PASS       – Credentials (API keys, JWTs) forwarded as tool arguments
13. SQLI             – SQL injection patterns in database tool arguments
14. RESOURCE-POISON  – Prompt injection embedded in tool responses or resources
15. CONFIG-POISON    – Writing to MCP config files (mcp.json, MCPoison-style)
16. OAUTH-DEPUTY     – OAuth redirect hijack, scope escalation, credential exposure
17. SESSION-FLAW     – Session ID in URL, session fixation, cookie manipulation
18. CROSS-TENANT     – Unauthorized tenant context switch or cross-tenant access
19. NEIGHBORJACK     – Unsafe 0.0.0.0 binding or DNS rebinding
20. A2A-SMUGGLE      – Multi-turn A2A session injection or message burst
21. A2A-IMPERSONATE  – A2A agent card mutation / impersonation
22. A2A-HIJACK       – A2A task hijacking
23. SUPPLY-CHAIN     – Malicious package (e.g. postmark-mcp BCC exfil)
24. SAMPLING-ABUSE   – Covert tool invocation via MCP sampling, resource theft
25. UNICODE-SMUGGLE  – Zero-width / tag characters hiding instructions
26. TOOL-POISON-TPA  – Hidden instructions in tool descriptions
27. SENSITIVE-DATA   – PII, secrets, or credentials leaked in responses
28. CROSS-CALL-CHAIN – Multi-step attack chain across sequential tool calls

Respond with JSON only:
{{"is_threat": boolean, "confidence": 0.0-1.0, "pattern": "PATTERN_NAME or null", "explanation": "one sentence"}}"""

_context_buffers: dict[str, deque] = {}

MAX_CONTEXT_PER_SERVER = 20


def record_context(server_name: str, tool_call: dict) -> None:
    """Append a tool call summary to the per-server rolling buffer."""
    if server_name not in _context_buffers:
        _context_buffers[server_name] = deque(maxlen=MAX_CONTEXT_PER_SERVER)
    _context_buffers[server_name].append(tool_call)


def get_context(server_name: str) -> list[dict]:
    """Return the recent tool call history for a server."""
    return list(_context_buffers.get(server_name, []))


async def analyze_with_gemini(
    tool_call: dict,
    context: list[dict],
    flagged_patterns: list[str] | None = None,
) -> dict | None:
    """Use Gemini to classify whether a tool call is an attack."""
    api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("CROSSFIRE_GEMINI_KEY")
    if not api_key:
        return None

    try:
        from google.adk.agents import LlmAgent
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        from google.genai import types

        agent = LlmAgent(
            name="crossfire_threat_analyzer",
            model="gemini-2.5-flash",
            instruction="You are a security analyst. Analyze MCP tool calls for attack patterns. Always respond with valid JSON.",
        )

        session_service = InMemorySessionService()
        runner = Runner(
            agent=agent,
            app_name="crossfire",
            session_service=session_service,
        )

        session = await session_service.create_session(
            app_name="crossfire",
            user_id="proxy",
        )

        flagged_str = ", ".join(flagged_patterns) if flagged_patterns else "(none)"
        prompt = GEMINI_PROMPT.format(
            context=json.dumps(context[-10:], indent=2),
            current=json.dumps(tool_call, indent=2),
            flagged=flagged_str,
        )

        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=prompt)],
        )

        async for event in runner.run_async(
            session_id=session.id,
            user_id="proxy",
            new_message=content,
        ):
            if event.is_final_response():
                response_text = event.content.parts[0].text
                try:
                    clean = response_text.strip()
                    if clean.startswith("```"):
                        clean = clean.split("\n", 1)[1].rsplit("```", 1)[0].strip()
                    return json.loads(clean)
                except json.JSONDecodeError:
                    sys.stderr.write(
                        f"[crossfire] Gemini returned non-JSON: {response_text[:200]}\n"
                    )
                    return None

    except ImportError:
        sys.stderr.write(
            "[crossfire] google-adk not installed, skipping Gemini analysis\n"
        )
        return None
    except Exception as exc:
        sys.stderr.write(f"[crossfire] Gemini analysis error: {exc}\n")
        return None


async def analyze_and_enrich(
    event: dict,
    server_name: str,
    context: list[dict] | None = None,
) -> dict:
    """Analyze an event with Gemini and add results to it.

    Uses the rolling context buffer for the given server when no explicit
    context is provided, and wraps the API call in a timeout.
    """
    if not event.get("threats"):
        return event

    if context is None:
        context = get_context(server_name)

    flagged = list(
        {t.get("pattern", "") for t in event.get("threats", []) if t.get("pattern")}
    )

    try:
        result = await asyncio.wait_for(
            analyze_with_gemini(
                tool_call={
                    "method": event.get("method"),
                    "params": event.get("params"),
                },
                context=context,
                flagged_patterns=flagged,
            ),
            timeout=GEMINI_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        sys.stderr.write(
            f"[crossfire] Gemini analysis timed out after {GEMINI_TIMEOUT_SECONDS}s\n"
        )
        return event

    if result and result.get("is_threat"):
        for threat in event.get("threats", []):
            threat["gemini_analysis"] = result

    return event
