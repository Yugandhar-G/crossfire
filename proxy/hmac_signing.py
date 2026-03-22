"""HMAC Event Signing -- cryptographic integrity for proxy-to-dashboard events.

Prevents event injection, tampering, and replay attacks using
HMAC-SHA256 with nonce + timestamp validation.
"""

import hashlib
import hmac
import json
import logging
import secrets
import time

logger = logging.getLogger("crossfire.hmac")

MAX_EVENT_AGE_SECONDS = 60
MAX_NONCE_CACHE = 10_000


class EventSigner:
    """Sign outgoing events with HMAC for integrity verification."""

    def __init__(self, secret: str, algorithm: str = "sha256"):
        if not secret:
            raise ValueError("HMAC secret must not be empty")
        self._secret = secret.encode("utf-8")
        self._hash_func = getattr(hashlib, algorithm, None)
        if self._hash_func is None:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def sign(self, event: dict) -> dict:
        signed = dict(event)
        signed["_hmac_nonce"] = secrets.token_hex(16)
        signed["_hmac_timestamp"] = time.time()
        canonical = self._canonicalize(signed)
        signed["_hmac_signature"] = hmac.new(
            self._secret, canonical, self._hash_func
        ).hexdigest()
        return signed

    def verify(self, event: dict) -> bool:
        sig = event.get("_hmac_signature")
        if not sig:
            return False
        ts = event.get("_hmac_timestamp", 0)
        if abs(time.time() - ts) > MAX_EVENT_AGE_SECONDS:
            return False
        check = {k: v for k, v in event.items() if k != "_hmac_signature"}
        expected = hmac.new(
            self._secret, self._canonicalize(check), self._hash_func
        ).hexdigest()
        return hmac.compare_digest(sig, expected)

    def _canonicalize(self, event: dict) -> bytes:
        clean = {k: v for k, v in event.items() if k != "_hmac_signature"}
        return json.dumps(
            clean, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")


class EventVerifier:
    """Verify HMAC signatures on received events with replay protection."""

    def __init__(self, secret: str, algorithm: str = "sha256"):
        self._signer = EventSigner(secret, algorithm)
        self._seen_nonces: set[str] = set()
        self._nonce_timestamps: list[tuple[float, str]] = []

    def verify(self, event: dict) -> tuple[bool, str]:
        for field in ("_hmac_signature", "_hmac_nonce", "_hmac_timestamp"):
            if field not in event:
                return False, f"missing_{field.lstrip('_hmac_')}"

        nonce = event["_hmac_nonce"]
        self._cleanup()
        if nonce in self._seen_nonces:
            return False, "replay_detected"

        if not self._signer.verify(event):
            return False, "invalid_signature"

        self._seen_nonces.add(nonce)
        self._nonce_timestamps.append((time.time(), nonce))
        return True, "valid"

    def _cleanup(self) -> None:
        cutoff = time.time() - MAX_EVENT_AGE_SECONDS * 2
        kept: list[tuple[float, str]] = []
        for ts, n in self._nonce_timestamps:
            if ts < cutoff:
                self._seen_nonces.discard(n)
            else:
                kept.append((ts, n))
        self._nonce_timestamps = kept
        if len(self._seen_nonces) > MAX_NONCE_CACHE:
            half = len(self._nonce_timestamps) // 2
            for _, n in self._nonce_timestamps[:half]:
                self._seen_nonces.discard(n)
            self._nonce_timestamps = self._nonce_timestamps[half:]
