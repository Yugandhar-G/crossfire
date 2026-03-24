# Contributing to Crossfire

Thanks for your interest in contributing to Crossfire! This guide covers everything you need to get started.

## Development Setup

**Requirements:**
- Python 3.10+
- Node.js 20+ (for dashboard development only)
- Git

```bash
git clone https://github.com/Yugandhar-G/crossfire.git
cd crossfire
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[gemini,dev]"
```

For dashboard UI development:

```bash
cd dashboard && npm ci && npm run build && cd ..
```

## Running Tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR. Current suite: 147+ tests.

## Code Style

- Follow PEP 8 conventions
- Type hints are encouraged on all new code
- Keep files under 400 lines where practical
- Use descriptive variable and function names

## How to Contribute

1. **Fork** the repository
2. **Create a branch** from `main` (`git checkout -b feat/my-feature`)
3. **Write tests** for new functionality
4. **Run the test suite** (`python -m pytest tests/ -v`)
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, etc.)
6. **Open a Pull Request** against `main`

## Adding a New Detector

Crossfire's detection engine is modular. To add a new detector:

1. Create a new file in `proxy/detectors/` (e.g., `my_detector.py`)
2. Define a detection function with signature:

```python
def detect_my_threat(method: str, params: dict) -> list[dict]:
    """Return a list of threat dicts, or empty list if clean."""
    threats = []
    # Your detection logic here
    if suspicious:
        threats.append({
            "detector": "my-detector",
            "severity": "high",       # low, medium, high, critical
            "label": "MY-THREAT",
            "description": "What was detected and why it matters",
        })
    return threats
```

3. Import and wire it into `proxy/proxy.py` in the detection pipeline
4. Add tests in `tests/` covering both positive (threat found) and negative (clean input) cases
5. Document the pattern in the README detection table

Use existing detectors like `path_traversal.py` or `sql_injection.py` as reference implementations.

## Contributor License Agreement

By submitting a Pull Request, you agree to the terms in [CLA.md](CLA.md). In short: you grant the project a license to use your contribution under the same MIT license, and you confirm you have the right to make the contribution.

## Reporting Bugs

Use the [Bug Report](https://github.com/Yugandhar-G/crossfire/issues/new?template=bug_report.yml) issue template.

## Requesting Features

Use the [Feature Request](https://github.com/Yugandhar-G/crossfire/issues/new?template=feature_request.yml) issue template.

## Proposing New Detectors

Use the [New Detector](https://github.com/Yugandhar-G/crossfire/issues/new?template=new_detector.yml) issue template. Include the attack pattern, any CVE references, and your proposed detection approach.

## Questions?

Open a [Discussion](https://github.com/Yugandhar-G/crossfire/discussions) or reach out at yugandhargopu1@gmail.com.
