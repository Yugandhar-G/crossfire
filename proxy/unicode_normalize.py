"""Unicode anti-evasion -- normalize homoglyphs before threat detection.

Attackers can bypass ASCII pattern matching by substituting visually
identical Unicode characters (Cyrillic a for Latin a, fullwidth digits,
zero-width characters, RTL overrides, combining marks, math alphanumeric, etc.).
"""

import re
import unicodedata

# --- Cyrillic -> Latin homoglyphs ---
_CYRILLIC = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u0406": "I", "\u0408": "J", "\u041a": "K",
    "\u041c": "M", "\u041e": "O", "\u0420": "P", "\u0422": "T",
    "\u0425": "X", "\u0423": "Y",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0455": "s", "\u0431": "b",
    "\u0432": "v", "\u043d": "n", "\u043a": "k", "\u0442": "t",
    "\u0433": "r",  # Cyrillic ge looks like r in some fonts
}

# --- Greek -> Latin homoglyphs ---
_GREEK = {
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a5": "Y", "\u03a7": "X",
    "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03bf": "o",
    "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x",
    "\u03ba": "k", "\u03bd": "v", "\u03c9": "w",
}

# --- Fullwidth ASCII (U+FF01 - U+FF5E) -> regular ASCII ---
_FULLWIDTH = {}
for _i in range(0xFF01, 0xFF5F):
    _FULLWIDTH[chr(_i)] = chr(_i - 0xFEE0)

# --- Punctuation / symbol homoglyphs ---
_PUNCTUATION = {
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
    "\u2014": "-", "\u2015": "-", "\u2212": "-",  # minus sign
    "\u2024": ".", "\u2025": "..", "\u2026": "...",
    "\uff0f": "/", "\u2044": "/", "\u2215": "/",  # division slash
    "\uff3c": "\\", "\u2216": "\\",  # set minus
    "\u2018": "'", "\u2019": "'", "\u201a": "'",  # smart quotes
    "\u201c": '"', "\u201d": '"', "\u201e": '"',
    "\u02bc": "'",  # modifier letter apostrophe
    "\u2039": "<", "\u203a": ">",
    "\uff08": "(", "\uff09": ")",
    "\uff3b": "[", "\uff3d": "]",
    "\uff5b": "{", "\uff5d": "}",
    "\u2768": "(", "\u2769": ")",
    "\uff1a": ":", "\uff1b": ";",
    "\uff0c": ",", "\uff0e": ".",
}

# --- Zero-width and invisible characters to strip ---
_ZERO_WIDTH = frozenset({
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\u2061",  # function application
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
    "\ufeff",  # BOM / zero width no-break space
    "\u00ad",  # soft hyphen
    "\u034f",  # combining grapheme joiner
    "\u061c",  # arabic letter mark
    "\u115f",  # hangul choseong filler
    "\u1160",  # hangul jungseong filler
    "\u17b4",  # khmer vowel inherent aq
    "\u17b5",  # khmer vowel inherent aa
    "\u180e",  # mongolian vowel separator
})

# --- RTL/LTR override characters to strip ---
_BIDI_CONTROLS = frozenset({
    "\u202a",  # LTR embedding
    "\u202b",  # RTL embedding
    "\u202c",  # pop directional
    "\u202d",  # LTR override
    "\u202e",  # RTL override
    "\u2066",  # LTR isolate
    "\u2067",  # RTL isolate
    "\u2068",  # first strong isolate
    "\u2069",  # pop directional isolate
})

_STRIP_CHARS = _ZERO_WIDTH | _BIDI_CONTROLS

# --- Combined homoglyph mapping ---
_HOMOGLYPHS: dict[str, str] = {}
_HOMOGLYPHS.update(_CYRILLIC)
_HOMOGLYPHS.update(_GREEK)
_HOMOGLYPHS.update(_FULLWIDTH)
_HOMOGLYPHS.update(_PUNCTUATION)

# --- Regex for combining diacritical marks (U+0300-U+036F) ---
_COMBINING_RE = re.compile(r"[\u0300-\u036f\u0337\u0338]")

# --- Math Alphanumeric Symbols (U+1D400-U+1D7FF) ---
# These map bold/italic/script/fraktur/etc variants to plain ASCII
_MATH_ALPHA_RANGES = [
    # Bold A-Z
    (0x1D400, 0x1D419, ord('A')),
    # Bold a-z
    (0x1D41A, 0x1D433, ord('a')),
    # Italic A-Z
    (0x1D434, 0x1D44D, ord('A')),
    # Italic a-z (with hole at h=0x1D455, use planck constant)
    (0x1D44E, 0x1D467, ord('a')),
    # Bold Italic A-Z
    (0x1D468, 0x1D481, ord('A')),
    # Bold Italic a-z
    (0x1D482, 0x1D49B, ord('a')),
    # Script A-Z
    (0x1D49C, 0x1D4B5, ord('A')),
    # Script a-z
    (0x1D4B6, 0x1D4CF, ord('a')),
    # Bold Script A-Z
    (0x1D4D0, 0x1D4E9, ord('A')),
    # Bold Script a-z
    (0x1D4EA, 0x1D503, ord('a')),
    # Fraktur A-Z
    (0x1D504, 0x1D51D, ord('A')),
    # Fraktur a-z
    (0x1D51E, 0x1D537, ord('a')),
    # Sans-Serif A-Z
    (0x1D5A0, 0x1D5B9, ord('A')),
    # Sans-Serif a-z
    (0x1D5BA, 0x1D5D3, ord('a')),
    # Sans-Serif Bold A-Z
    (0x1D5D4, 0x1D5ED, ord('A')),
    # Sans-Serif Bold a-z
    (0x1D5EE, 0x1D607, ord('a')),
    # Sans-Serif Italic A-Z
    (0x1D608, 0x1D621, ord('A')),
    # Sans-Serif Italic a-z
    (0x1D622, 0x1D63B, ord('a')),
    # Sans-Serif Bold Italic A-Z
    (0x1D63C, 0x1D655, ord('A')),
    # Sans-Serif Bold Italic a-z
    (0x1D656, 0x1D66F, ord('a')),
    # Monospace A-Z
    (0x1D670, 0x1D689, ord('A')),
    # Monospace a-z
    (0x1D68A, 0x1D6A3, ord('a')),
    # Bold digits 0-9
    (0x1D7CE, 0x1D7D7, ord('0')),
    # Double-struck digits 0-9
    (0x1D7D8, 0x1D7E1, ord('0')),
    # Sans-Serif digits 0-9
    (0x1D7E2, 0x1D7EB, ord('0')),
    # Sans-Serif Bold digits 0-9
    (0x1D7EC, 0x1D7F5, ord('0')),
    # Monospace digits 0-9
    (0x1D7F6, 0x1D7FF, ord('0')),
]

_MATH_ALPHA: dict[str, str] = {}
for _start, _end, _base in _MATH_ALPHA_RANGES:
    for _cp in range(_start, _end + 1):
        _MATH_ALPHA[chr(_cp)] = chr(_base + (_cp - _start))

_HOMOGLYPHS.update(_MATH_ALPHA)


def normalize_text(text: str) -> str:
    """Full anti-evasion normalization pipeline:
    1. NFKC unicode normalization (decomposes compatibility chars)
    2. Strip zero-width and bidi control characters
    3. Remove combining diacritical marks (strikethrough, overlays)
    4. Replace known homoglyphs (Cyrillic, Greek, fullwidth, math alpha, etc.)
    """
    if not text:
        return text
    # NFKC normalizes compatibility characters (superscripts, etc.)
    normalized = unicodedata.normalize("NFKC", text)
    # Strip invisible characters
    normalized = "".join(ch for ch in normalized if ch not in _STRIP_CHARS)
    # Remove combining marks used for visual obfuscation
    normalized = _COMBINING_RE.sub("", normalized)
    # Replace homoglyphs
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
