"""Tests for HMAC signing, verification, and replay protection."""

import time

from proxy.hmac_signing import EventSigner, EventVerifier, MAX_EVENT_AGE_SECONDS


def _sample_event() -> dict:
    return {
        "id": "test-001",
        "timestamp": "2025-01-01T00:00:00Z",
        "server": "demo",
        "method": "tools/call",
    }


def test_sign_and_verify_roundtrip():
    signer = EventSigner(secret="test-secret")
    event = _sample_event()
    signed = signer.sign(event)

    assert "_hmac_signature" in signed
    assert "_hmac_nonce" in signed
    assert "_hmac_timestamp" in signed
    assert signer.verify(signed)


def test_tampered_event_fails_verification():
    signer = EventSigner(secret="test-secret")
    signed = signer.sign(_sample_event())
    signed["server"] = "evil-server"
    assert not signer.verify(signed)


def test_wrong_secret_fails_verification():
    signer = EventSigner(secret="secret-a")
    signed = signer.sign(_sample_event())

    other = EventSigner(secret="secret-b")
    assert not other.verify(signed)


def test_missing_signature_fails():
    signer = EventSigner(secret="test-secret")
    event = _sample_event()
    assert not signer.verify(event)


def test_expired_event_fails(monkeypatch):
    signer = EventSigner(secret="test-secret")
    signed = signer.sign(_sample_event())
    future = time.time() + MAX_EVENT_AGE_SECONDS + 10
    monkeypatch.setattr(time, "time", lambda: future)
    assert not signer.verify(signed)


def test_verifier_detects_replay():
    signer = EventSigner(secret="test-secret")
    verifier = EventVerifier(secret="test-secret")
    signed = signer.sign(_sample_event())

    ok1, reason1 = verifier.verify(signed)
    assert ok1
    assert reason1 == "valid"

    ok2, reason2 = verifier.verify(signed)
    assert not ok2
    assert reason2 == "replay_detected"


def test_verifier_accepts_distinct_nonces():
    signer = EventSigner(secret="test-secret")
    verifier = EventVerifier(secret="test-secret")

    ok1, _ = verifier.verify(signer.sign(_sample_event()))
    ok2, _ = verifier.verify(signer.sign(_sample_event()))
    assert ok1
    assert ok2


def test_verifier_rejects_missing_fields():
    verifier = EventVerifier(secret="test-secret")
    ok, reason = verifier.verify({"id": "test"})
    assert not ok
    assert "missing" in reason


def test_verifier_rejects_bad_signature():
    signer = EventSigner(secret="test-secret")
    verifier = EventVerifier(secret="test-secret")
    signed = signer.sign(_sample_event())
    signed["_hmac_signature"] = "deadbeef"
    ok, reason = verifier.verify(signed)
    assert not ok
    assert reason == "invalid_signature"


def test_cleanup_evicts_old_nonces(monkeypatch):
    signer = EventSigner(secret="test-secret")
    verifier = EventVerifier(secret="test-secret")

    signed = signer.sign(_sample_event())
    verifier.verify(signed)
    assert signed["_hmac_nonce"] in verifier._seen_nonces

    future = time.time() + MAX_EVENT_AGE_SECONDS * 3
    monkeypatch.setattr(time, "time", lambda: future)
    verifier._cleanup()
    assert signed["_hmac_nonce"] not in verifier._seen_nonces
