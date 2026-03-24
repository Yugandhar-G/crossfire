# Changelog

All notable changes to Crossfire are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-03-23

### Added
- **40+ security detectors** covering all known MCP/A2A attack patterns
- **Encoding decode layer** (`decode_layer.py`) - Detects and decodes Base64, hex, URL-encoded, and HTML-entity-encoded payloads before analysis
- **New detector modules**: XSS, XXE, SSTI, SSRF, LDAP/XPath injection, deserialization attacks, zip slip
- **A2A protocol support** - First security proxy for Google's Agent-to-Agent protocol
- **Active scanner** (`crossfire scan`) - Spawn and probe MCP servers for vulnerabilities
- **Guardian mode** - Block critical threats in real-time (configurable via dashboard)
- **HMAC event signing** - Tamper-evident audit trail
- **Unicode normalization** - Anti-evasion preprocessing for zero-width characters
- **Cross-call chain tracker** - Detect multi-step attack sequences across tool calls
- **Gemini AI analysis layer** - Context-aware threat classification using Gemini 2.5 Flash
- **npm wrapper package** - `npx crossfire-mcp` auto-installs from PyPI
- **IDE auto-detection** - Cursor, VS Code, Claude Desktop, Windsurf, Antigravity
- **Comprehensive test suite** - 147 tests covering all detectors and core proxy logic

### Changed
- Detection engine restructured into modular `proxy/detectors/` package
- Protocol layer hardened with message size limits and framing validation
- Dashboard API rate-limited to 200 events/sec
- Improved CLI with `start`, `install`, `uninstall`, `scan`, `doctor`, `demo`, `ping` subcommands

### Fixed
- npm postinstall fallback when `crossfire` not on PATH
- Robust Python environment detection in npm wrapper

## [0.1.0] - 2025-03-20

### Added
- Initial hackathon release
- MCP stdio man-in-the-middle proxy
- Basic rule engine (credential theft, shell injection, exfiltration)
- React + React Flow dashboard with WebSocket streaming
- FastAPI dashboard server
- YAML configuration support
- Demo scenario with poisoned weather server

[0.2.0]: https://github.com/Yugandhar-G/crossfire/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Yugandhar-G/crossfire/releases/tag/v0.1.0
