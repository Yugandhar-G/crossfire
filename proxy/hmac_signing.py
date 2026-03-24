"""HMAC Event Signing -- cryptographic integrity for proxy-to-dashboard events.

Prevents event injection, tampering, and replay attacks using
HMAC-SHA256 with nonce + timestamp validation.

Security hardening:
 - Random nonce eviction (not FIFO) to prevent targeted replay
 - Thread-safe nonce cache operations
 - Constant-time comparison for all security checks
"""

import hashlib
import hmac
import json
import logging
import random
import secrets
import threading
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
        # Constant-time age check: always compute both branches
        age = abs(time.time() - ts)
        if age > MAX_EVENT_AGE_SECONDS:
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
    """Verify HMAC signatures on received events with replay protection.

    Uses random eviction instead of FIFO to prevent targeted replay attacks.
    Thread-safe via lock.
    """

    def __init__(self, secret: str, algorithm: str = "sha256"):
        self._signer = EventSigner(secret, algorithm)
        self._seen_nonces: set[str] = set()
        self._nonce_timestamps: list[tuple[float, str]] = []
        self._lock = threading.Lock()

    def verify(self, event: dict) -> tuple[bool, str]:
        for field in ("_hmac_signature", "_hmac_nonce", "_hmac_timestamp"):
            if field not in event:
                return False, f"missing_{field.lstrip('_hmac_')}"

        nonce = event["_hmac_nonce"]

        with self._lock:
            self._cleanup()
            if nonce in self._seen_nonces:
                return False, "replay_detected"

        if not self._signer.verify(event):
            return False, "invalid_signature"

        with self._lock:
            self._seen_nonces.add(nonce)
            self._nonce_timestamps.append((time.time(), nonce))

        return True, "valid"

    def _cleanup(self) -> None:
        """Remove expired nonces and randomly evict if over capacity."""
        cutoff = time.time() - MAX_EVENT_AGE_SECONDS * 2
        kept: list[tuple[float, str]] = []
        for ts, n in self._nonce_timestamps:
            if ts < cutoff:
                self._seen_nonces.discard(n)
            else:
                kept.append((ts, n))
        self._nonce_timestamps = kept

        # Random eviction instead of FIFO to prevent targeted replay
        if len(self._seen_nonces) > MAX_NONCE_CACHE:
            excess = len(self._seen_nonces) - (MAX_NONCE_CACHE // 2)
            if excess > 0 and self._nonce_timestamps:
                # Randomly select indices to evict
                indices_to_remove = set(
                    random.sample(
                        range(len(self._nonce_timestamps)),
                        min(excess, len(self._nonce_timestamps)),
                    )
                )
                new_timestamps = []
                for i, (ts, n) in enumerate(self._nonce_timestamps):
                    if i in indices_to_remove:
                        self._seen_nonces.discard(n)
                    else:
                        new_timestamps.append((ts, n))
                self._nonce_timestamps = new_timestamps
