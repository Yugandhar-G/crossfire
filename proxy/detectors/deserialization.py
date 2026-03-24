"""Insecure Deserialization detection.

Detects deserialization gadgets and unsafe deserialization calls across
Python (pickle, yaml.load, marshal), Java (ObjectInputStream, commons-collections),
.NET (BinaryFormatter), Ruby (Marshal.load), PHP (unserialize), and Node.js.
Reference: OWASP Deserialization, CWE-502.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_DESER_PATTERNS = [
    # Python unsafe deserialization
    re.compile(r"\bpickle\.(?:loads?|Unpickler)\s*\(", re.IGNORECASE),
    re.compile(r"\bcPickle\.(?:loads?|Unpickler)\s*\(", re.IGNORECASE),
    re.compile(r"\b_pickle\.loads?\s*\("),
    re.compile(r"\byaml\.(?:load|unsafe_load|full_load)\s*\("),
    re.compile(r"\byaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:Safe|Base)Loader)"),
    re.compile(r"\bmarshal\.loads?\s*\("),
    re.compile(r"\bshelve\.open\s*\("),
    re.compile(r"\bjsonpickle\.decode\s*\("),
    re.compile(r"\bdill\.loads?\s*\("),
    re.compile(r"\bcloudpickle\.loads?\s*\("),
    # Python pickle protocol magic bytes (base64 or hex)
    re.compile(r"\\x80\\x0[2-5]"),  # pickle protocol 2-5
    re.compile(r"gASV"),  # base64 pickle header

    # Java deserialization
    re.compile(r"\bObjectInputStream\b"),
    re.compile(r"\breadObject\s*\("),
    re.compile(r"\bXMLDecoder\b"),
    re.compile(r"rO0AB"),  # base64 Java serialized object header
    re.compile(r"\\xac\\xed\\x00\\x05"),  # hex Java magic bytes
    re.compile(r"\bcommons-collections\b.*\bInvokerTransformer\b", re.IGNORECASE),
    re.compile(r"\bTemplatesImpl\b"),
    re.compile(r"\bBadAttributeValueExpException\b"),
    re.compile(r"\bSnakeYAML\b.*\b!!.*\bjavax?\.", re.IGNORECASE),

    # .NET deserialization
    re.compile(r"\bBinaryFormatter\b"),
    re.compile(r"\bNetDataContractSerializer\b"),
    re.compile(r"\bLosFormatter\b"),
    re.compile(r"\bObjectStateFormatter\b"),
    re.compile(r"\bSoapFormatter\b"),
    re.compile(r"\bTypeNameHandling\s*[=:]\s*(?:Auto|Objects|All|Arrays)\b", re.IGNORECASE),
    re.compile(r"AAEAAAD/////"),  # base64 .NET serialized object

    # Ruby deserialization
    re.compile(r"\bMarshal\.load\b"),
    re.compile(r"\bMarshal\.restore\b"),
    re.compile(r"\bYAML\.load\b(?!.*safe)"),

    # PHP deserialization
    re.compile(r"\bunserialize\s*\("),
    re.compile(r'O:\d+:"[^"]+":'),  # PHP serialized object format
    re.compile(r"\bphar://", re.IGNORECASE),

    # Node.js deserialization
    re.compile(r"\bnode-serialize\b", re.IGNORECASE),
    re.compile(r"\bcryo\.parse\s*\("),
    re.compile(r"\bserialize-javascript\b.*\beval\b", re.IGNORECASE),
    re.compile(r"_\$\$ND_FUNC\$\$_"),  # node-serialize RCE payload marker
]


def detect_deserialization(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect insecure deserialization patterns in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("deserialization", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _DESER_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="insecure_deserialization",
                            severity="critical",
                            detail=f"Deserialization in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="DESER",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] deserialization error: {exc}\n")
        return []
