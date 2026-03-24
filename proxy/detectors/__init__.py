"""Crossfire threat detection engine.

Detectors cover 40+ attack categories:
 - Core: CRED-THEFT, SHELL-INJECT, PROMPT-RELAY, PRIV-ESCAPE, EXFIL-NET, MEM-POISON
 - Path: PATH-TRAVERSE, ZIP-SLIP
 - Injection: SQLI, XXE, SSTI, SSRF, XSS, LDAP-INJECT, XPATH-INJECT, DESER
 - Auth: TOKEN-PASS, SESSION-FLAW, OAUTH-DEPUTY
 - Protocol: NEIGHBORJACK, RESOURCE-POISON, CONFIG-POISON, CROSS-TENANT
 - Chain: Cross-call attack sequence detection
 - A2A: Agent card impersonation, session smuggling
 - AI: Gemini-powered contextual analysis
"""

from shared.event_schema import Threat

__all__ = ["Threat"]
