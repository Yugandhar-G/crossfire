"""Multi-layer encoding detection and decoding for evasion resistance.

Attackers encode payloads in base64, hex, URL-encoding (single and double),
octal, and Unicode escapes to bypass pattern matching. This module decodes
all layers before handing content to detectors.
"""

import base64
import re
import sys
from urllib.parse import unquote


# --- URL decode (multi-pass until stable) ---
def _url_decode(text: str, max_passes: int = 3) -> str:
    """Decode URL-encoded strings, including double/triple encoding."""
    result = text
    for _ in range(max_passes):
        decoded = unquote(result)
        if decoded == result:
            break
        result = decoded
    return result


# --- Hex escape sequences (\x63\x75\x72\x6c -> curl) ---
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _decode_hex_escapes(text: str) -> str:
    def _replace(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return _HEX_ESCAPE_RE.sub(_replace, text)


# --- Unicode escape sequences (\u0063 -> c) ---
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _decode_unicode_escapes(text: str) -> str:
    def _replace(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return _UNICODE_ESCAPE_RE.sub(_replace, text)


# --- Octal escape sequences (\143\165\162\154 -> curl) ---
_OCTAL_ESCAPE_RE = re.compile(r"\\([0-3][0-7]{2})")


def _decode_octal_escapes(text: str) -> str:
    def _replace(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 8))
        except (ValueError, OverflowError):
            return m.group(0)
    return _OCTAL_ESCAPE_RE.sub(_replace, text)


# --- HTML entities (&#99;&#117;&#114;&#108; -> curl) ---
_HTML_DECIMAL_RE = re.compile(r"&#(\d{1,5});")
_HTML_HEX_RE = re.compile(r"&#x([0-9a-fA-F]{1,4});")


def _decode_html_entities(text: str) -> str:
    def _dec_replace(m: re.Match) -> str:
        try:
            cp = int(m.group(1))
            if 0 < cp < 0x110000:
                return chr(cp)
        except (ValueError, OverflowError):
            pass
        return m.group(0)

    def _hex_replace(m: re.Match) -> str:
        try:
            cp = int(m.group(1), 16)
            if 0 < cp < 0x110000:
                return chr(cp)
        except (ValueError, OverflowError):
            pass
        return m.group(0)

    result = _HTML_DECIMAL_RE.sub(_dec_replace, text)
    return _HTML_HEX_RE.sub(_hex_replace, result)


# --- Base64 detection and decoding ---
_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _try_decode_base64(text: str) -> str:
    """Attempt to decode base64 segments inline. Returns original + decoded."""
    decoded_parts = []
    for match in _B64_RE.finditer(text):
        candidate = match.group(0)
        try:
            raw = base64.b64decode(candidate, validate=True)
            decoded_str = raw.decode("utf-8", errors="ignore")
            if decoded_str.isprintable() and len(decoded_str) > 4:
                decoded_parts.append(decoded_str)
        except Exception:
            continue
    if decoded_parts:
        return text + " " + " ".join(decoded_parts)
    return text


# --- Null byte stripping ---
def _strip_null_bytes(text: str) -> str:
    return text.replace("\x00", "")


# --- Shell quote/escape stripping (c''url -> curl, c\url -> curl) ---
_SHELL_EMPTY_QUOTES_RE = re.compile(r"(?:''){1,}|(?:\"\")+")
_SHELL_BACKSLASH_RE = re.compile(r"\\(?=[a-zA-Z0-9])")
_SHELL_IFS_RE = re.compile(r"\$\{IFS\}", re.IGNORECASE)
_SHELL_VARIABLE_RE = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _strip_shell_obfuscation(text: str) -> str:
    """Remove shell-level obfuscation tricks."""
    result = _SHELL_EMPTY_QUOTES_RE.sub("", text)
    result = _SHELL_IFS_RE.sub(" ", result)
    result = _SHELL_BACKSLASH_RE.sub("", result)
    return result


# --- Comment stripping (/* ... */ and # to end of line within values) ---
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_SQL_INLINE_COMMENT_RE = re.compile(r"/\*!\d*\s*(.*?)\*/", re.DOTALL)


def _strip_comments(text: str) -> str:
    """Strip block comments but preserve content of MySQL conditional comments."""
    result = _SQL_INLINE_COMMENT_RE.sub(r"\1", text)
    result = _BLOCK_COMMENT_RE.sub(" ", result)
    return result


def decode_all_layers(text: str) -> str:
    """Apply all decoding layers to produce a normalized string for detection.

    Returns the fully decoded text. The original text is NOT modified;
    detectors should run patterns against BOTH the original and decoded versions.
    """
    try:
        if not text or not isinstance(text, str):
            return text or ""

        result = text
        # 1. Strip null bytes
        result = _strip_null_bytes(result)
        # 2. URL decode (multi-pass)
        result = _url_decode(result)
        # 3. HTML entities
        result = _decode_html_entities(result)
        # 4. Hex escapes
        result = _decode_hex_escapes(result)
        # 5. Unicode escapes
        result = _decode_unicode_escapes(result)
        # 6. Octal escapes
        result = _decode_octal_escapes(result)
        # 7. Shell obfuscation
        result = _strip_shell_obfuscation(result)
        # 8. SQL/block comment stripping
        result = _strip_comments(result)
        # 9. Base64 (append decoded content)
        result = _try_decode_base64(result)

        return result
    except Exception as exc:
        sys.stderr.write(f"[crossfire] decode_layer error: {exc}\n")
        return text or ""


def decode_arguments(arguments: dict) -> dict:
    """Recursively decode all string values in arguments dict."""
    if not isinstance(arguments, dict):
        return arguments
    result = {}
    for key, value in arguments.items():
        if isinstance(value, str):
            result[key] = decode_all_layers(value)
        elif isinstance(value, dict):
            result[key] = decode_arguments(value)
        elif isinstance(value, list):
            result[key] = [
                decode_all_layers(item)
                if isinstance(item, str)
                else decode_arguments(item)
                if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            result[key] = value
    return result
