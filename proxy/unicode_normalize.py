"""Unicode anti-evasion -- normalize homoglyphs before threat detection.

Attackers can bypass ASCII pattern matching by substituting visually
identical Unicode characters (Cyrillic a for Latin a, fullwidth digits, etc.).
"""

import unicodedata

_HOMOGLYPHS = {
    "\u0410": "A",
    "\u0412": "B",
    "\u0421": "C",
    "\u0415": "E",
    "\u041d": "H",
    "\u041a": "K",
    "\u041c": "M",
    "\u041e": "O",
    "\u0420": "P",
    "\u0422": "T",
    "\u0425": "X",
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\uff10": "0",
    "\uff11": "1",
    "\uff12": "2",
    "\u2010": "-",
    "\u2011": "-",
    "\u2012": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2024": ".",
    "\u2025": "..",
    "\uff0f": "/",
    "\u2044": "/",
    "\uff3c": "\\",
}


def normalize_text(text: str) -> str:
    """NFC-normalize and replace common homoglyphs used in evasion."""
    if not text:
        return text
    normalized = unicodedata.normalize("NFC", text)
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in normalized)


def normalize_arguments(arguments: dict) -> dict:
    """Recursively normalize all string values in an arguments dict."""
    if not isinstance(arguments, dict):
        return arguments
    result = {}
    for key, value in arguments.items():
        if isinstance(value, str):
            result[key] = normalize_text(value)
        elif isinstance(value, dict):
            result[key] = normalize_arguments(value)
        elif isinstance(value, list):
            result[key] = [
                normalize_text(item)
                if isinstance(item, str)
                else normalize_arguments(item)
                if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            result[key] = value
    return result
