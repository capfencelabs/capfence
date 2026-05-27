"""Tests for Ed25519 keypair management."""

import os
import tempfile
import time

from capfence.core.keys import (
    generate_keypair,
    load_keypair,
    ensure_keypair,
    sign_entry,
    verify_entry,
    _private_key_path,
    _public_key_path,
)
from capfence import ActionEvent, ExecutionVerdict
from capfence.core.audit import AuditLogger


class TestKeypairLifecycle:
    def test_generate_and_load(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("HOME", tmp)
            pub, priv = generate_keypair()
            assert pub
            assert priv
            loaded = load_keypair()
            assert loaded is not None
            assert loaded[0] == pub
            assert loaded[1] == priv

    def test_ensure_keypair_idempotent(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("HOME", tmp)
            pub1, priv1 = ensure_keypair()
            pub2, priv2 = ensure_keypair()
            assert pub1 == pub2
            assert priv1 == priv2

    def test_keys_dir_permissions(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("HOME", tmp)
            generate_keypair()
            assert _private_key_path().exists()
            assert _public_key_path().exists()
            # Private key should be readable only by owner (0o600)
            mode = os.stat(_private_key_path()).st_mode & 0o777
            assert mode == 0o600


class TestSignVerify:
    def test_roundtrip(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("HOME", tmp)
            pub, priv = generate_keypair()
            fields = {"agent_id": "a", "decision": "pass", "timestamp": 1.0}
            sig = sign_entry(fields, priv)
            assert verify_entry(fields, sig, pub) is True

    def test_tampered_fields_fails(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("HOME", tmp)
            pub, priv = generate_keypair()
            fields = {"agent_id": "a", "decision": "pass", "timestamp": 1.0}
            sig = sign_entry(fields, priv)
            bad_fields = {"agent_id": "a", "decision": "fail", "timestamp": 1.0}
            assert verify_entry(bad_fields, sig, pub) is False

    def test_wrong_key_fails(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("HOME", tmp)
            pub1, priv1 = generate_keypair()
            pub2, priv2 = generate_keypair()
            fields = {"agent_id": "a", "decision": "pass", "timestamp": 1.0}
            sig = sign_entry(fields, priv1)
            assert verify_entry(fields, sig, pub2) is False

    def test_invalid_signature_encoding_fails(self):
        fields = {"agent_id": "a", "decision": "pass", "timestamp": 1.0}
        assert verify_entry(fields, "not base64", "not base64") is False


class TestSignedAuditVerification:
    def test_signed_audit_log_verifies_and_detects_tampering(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("HOME", tmp)
            audit = AuditLogger(db_path=":memory:", sign_entries=True)
            event = ActionEvent.create(
                actor="agent",
                action="read",
                resource="filesystem",
                environment="production",
                risk="low",
            )
            audit.record_event(
                ExecutionVerdict(
                    authorized=True,
                    decision="allow",
                    reason="policy_allow",
                    event=event,
                    timestamp=time.time(),
                )
            )

            valid, errors = audit.verify()
            assert valid is True
            assert errors == []

            audit._db.execute("UPDATE audit_events SET signature = ? WHERE id = 1", ("tampered",))
            valid_after, errors_after = audit.verify()
            assert valid_after is False
            assert any("signature verification failed" in error for error in errors_after)
