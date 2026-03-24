# Security Policy

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, report them via email:

**Email:** yugandhargopu1@gmail.com
**Subject line:** `[SECURITY] Crossfire - <brief description>`

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Response SLA

| Action | Timeframe |
|--------|-----------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix for critical issues | 14 days |
| Public disclosure | After fix is released |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x | Yes |
| 0.1.x | No |
| < 0.1 | No |

## Scope

The following are in scope for security reports:

- Proxy bypass (attacks evading detection)
- False negatives in detectors (known attack patterns not caught)
- Vulnerabilities in the dashboard server (XSS, injection, auth bypass)
- Information disclosure through audit logs or events
- Denial of service against the proxy or dashboard

The following are out of scope:

- Issues in upstream dependencies (report to the upstream project)
- Attacks that require local machine access (Crossfire is a local tool)
- Social engineering

## Recognition

We will credit security researchers in the CHANGELOG and README (with your permission) for responsibly disclosed vulnerabilities.

## Security Design Principles

Crossfire follows these principles:

1. **Local-first**: No data leaves your machine unless you explicitly configure Gemini AI analysis
2. **Transparent proxy**: Never modifies tool call content
3. **Defense in depth**: Three detection layers (rules, cross-call, AI)
4. **Audit everything**: JSONL audit log with optional HMAC signing
5. **Fail open by default**: Monitor mode logs but does not block (Guardian mode opts into blocking)
