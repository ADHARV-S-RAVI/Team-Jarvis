"""Cryptographic provider and protected vault tests (Stage 3)."""

from __future__ import annotations

from pathlib import Path
import sqlite3

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from backend.app.crypto.provider import (
    CryptoError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf_sha256,
    hmac_sha256_hex,
    hmac_sha256_verify,
    ml_kem_decapsulate,
    ml_kem_encapsulate,
    ml_kem_generate_keypair,
    random_bytes,
    run_crypto_self_test,
    sha256_hex,
)
from backend.app.db.models import VaultEntry
from backend.app.db.session import create_db_engine, get_db
from backend.app.keys.service import KeyMaterialStore, generate_key_version
from backend.app.main import create_app


# --- Cryptographic Provider & Official KAT Tests ---


def test_crypto_self_test_passes() -> None:
    res = run_crypto_self_test()
    assert res["ml_kem_768"] == "ok"
    assert res["aes_256_gcm"] == "ok"
    assert res["hkdf_sha_256"] == "ok"


def test_ml_kem_768_encapsulate_decapsulate_and_wrong_key() -> None:
    pk, sk = ml_kem_generate_keypair()
    ct, ss1 = ml_kem_encapsulate(pk)
    ss2 = ml_kem_decapsulate(sk, ct)
    assert ss1 == ss2
    assert len(ss1) == 32

    # Wrong secret key yields a different shared secret (implicit rejection)
    _, sk_other = ml_kem_generate_keypair()
    ss_other = ml_kem_decapsulate(sk_other, ct)
    assert ss_other != ss1

    with pytest.raises(CryptoError):
        ml_kem_encapsulate(b"short")


def test_aes_gcm_encrypt_decrypt_tamper_and_nonce_uniqueness() -> None:
    key = random_bytes(32)
    aad = b"schema=v1|resource=r1"
    s1 = aes_gcm_encrypt(key, b"sensitive-payload", aad=aad)
    s2 = aes_gcm_encrypt(key, b"sensitive-payload", aad=aad)

    # Unique nonces per encryption
    assert s1.nonce != s2.nonce
    assert s1.ciphertext != s2.ciphertext

    pt = aes_gcm_decrypt(key, nonce=s1.nonce, ciphertext=s1.ciphertext, tag=s1.tag, aad=aad)
    assert pt == b"sensitive-payload"

    # Ciphertext tamper fails closed
    tampered_ct = bytes([s1.ciphertext[0] ^ 0xFF]) + s1.ciphertext[1:]
    with pytest.raises(CryptoError):
        aes_gcm_decrypt(key, nonce=s1.nonce, ciphertext=tampered_ct, tag=s1.tag, aad=aad)

    # Tag tamper fails closed
    tampered_tag = bytes([s1.tag[0] ^ 0xFF]) + s1.tag[1:]
    with pytest.raises(CryptoError):
        aes_gcm_decrypt(key, nonce=s1.nonce, ciphertext=s1.ciphertext, tag=tampered_tag, aad=aad)

    # AAD tamper fails closed
    with pytest.raises(CryptoError):
        aes_gcm_decrypt(key, nonce=s1.nonce, ciphertext=s1.ciphertext, tag=s1.tag, aad=b"wrong-aad")


def test_hkdf_rfc5869_test_vectors() -> None:
    # RFC 5869 Appendix A.1 Test Case 1
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert hkdf_sha256(ikm, 42, salt=salt, info=info) == expected

    # Purpose separation produces distinct keys
    k_dek = hkdf_sha256(ikm, 32, info=b"qshield:dek")
    k_audit = hkdf_sha256(ikm, 32, info=b"qshield:audit")
    assert k_dek != k_audit


def test_hmac_and_sha256_rfc4231_vector() -> None:
    # RFC 4231 Test Case 2 (Jefe)
    key = b"Jefe"
    msg = b"what do ya want for nothing?"
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    mac = hmac_sha256_hex(key, msg)
    assert mac == expected
    assert hmac_sha256_verify(key, msg, expected) is True
    assert hmac_sha256_verify(key, b"tampered", expected) is False
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# --- Protected Vault & Key Management Integration Tests ---


@pytest.fixture()
def vault_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "vault_test.db"
    db_url = f"sqlite:///{db_file}"
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("QSHIELD_KEY_STORE_DIR", str(key_dir))

    from backend.app.config import get_settings

    get_settings.cache_clear()

    alembic_cfg = Config("backend/alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(alembic_cfg, "head")

    engine = create_db_engine(db_url)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    app = create_app()

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, db_file, TestingSession
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
        get_settings.cache_clear()


def test_vault_ciphertext_persistence_and_plaintext_absence(vault_env) -> None:
    client, db_file, TestingSession = vault_env

    client.post("/api/v1/identities", json={"id": "alice", "display_label": "Alice", "role": "Owner/User"})
    client.post("/api/v1/identities", json={"id": "bob", "display_label": "Bob", "role": "Owner/User"})
    client.post("/api/v1/devices", json={"id": "dev-a", "owner_actor_id": "alice", "credential_fingerprint": "fp-alice-1"})
    client.post("/api/v1/devices", json={"id": "dev-b", "owner_actor_id": "bob", "credential_fingerprint": "fp-bob-1"})

    s_a = client.post("/api/v1/sessions", json={"actor_id": "alice", "device_id": "dev-a", "peer_id": "vault"}).json()
    s_b = client.post("/api/v1/sessions", json={"actor_id": "bob", "device_id": "dev-b", "peer_id": "vault"}).json()

    secret_plaintext = "ULTRA_SENSITIVE_QUANTUM_RECOVERY_NOTE_987654"
    store_resp = client.post(
        "/api/v1/vault/resources",
        json={
            "resource_id": "vault-doc-1",
            "owner_actor_id": "alice",
            "plaintext": secret_plaintext,
            "key_version": 1,
        },
    )
    assert store_resp.status_code == 201
    assert secret_plaintext not in store_resp.text

    # Plaintext must NEVER appear anywhere in raw SQLite file bytes
    raw_db_bytes = db_file.read_bytes()
    assert secret_plaintext.encode("utf-8") not in raw_db_bytes

    # Verify VaultEntry fields & key-version association
    with TestingSession() as db:
        entry = db.get(VaultEntry, "vault-doc-1")
        assert entry is not None
        assert entry.algorithm == "AES-256-GCM"
        assert entry.key_version == 1
        assert len(entry.nonce_b64) > 0
        assert len(entry.tag_b64) > 0

    # Authorized owner read returns plaintext
    ok_read = client.post(
        "/api/v1/vault/resources/vault-doc-1/read",
        json={
            "actor_id": "alice",
            "session_id": s_a["id"],
            "session_token": s_a["session_token"],
            "device_id": "dev-a",
            "peer_id": "vault",
        },
    )
    assert ok_read.status_code == 200
    assert ok_read.json()["plaintext"] == secret_plaintext
    assert ok_read.json()["key_version"] == 1

    # Unauthorized cross-user read returns 403 and zero plaintext/ciphertext/key leakage
    bad_read = client.post(
        "/api/v1/vault/resources/vault-doc-1/read",
        json={
            "actor_id": "bob",
            "session_id": s_b["id"],
            "session_token": s_b["session_token"],
            "device_id": "dev-b",
            "peer_id": "vault",
        },
    )
    assert bad_read.status_code == 403
    assert secret_plaintext not in bad_read.text
    assert "ciphertext" not in bad_read.text

    # Revoke Alice -> subsequent vault read denied
    client.post(
        "/api/v1/revocations",
        json={"subject_type": "actor", "subject_id": "alice", "reason": "Compromise"},
    )
    revoked_read = client.post(
        "/api/v1/vault/resources/vault-doc-1/read",
        json={
            "actor_id": "alice",
            "session_id": s_a["id"],
            "session_token": s_a["session_token"],
            "device_id": "dev-a",
            "peer_id": "vault",
        },
    )
    assert revoked_read.status_code == 403
    assert secret_plaintext not in revoked_read.text


def test_key_generation_separates_metadata_and_secret_material(vault_env) -> None:
    client, _, TestingSession = vault_env

    # Ensure defaults seeded
    client.post("/api/v1/identities", json={"id": "carol", "display_label": "Carol", "role": "Owner/User"})

    gen_resp = client.post("/api/v1/keys/generate", json={"algorithm": "AES-256-GCM", "state": "ACTIVE"})
    assert gen_resp.status_code == 201
    meta = gen_resp.json()
    assert meta["version"] >= 2
    assert meta["state"] == "ACTIVE"
    assert "secret" not in meta and "key_material" not in meta

    keys_list = client.get("/api/v1/keys")
    assert keys_list.status_code == 200
    assert len(keys_list.json()) >= 2

    # KeyMaterialStore isolates secret material from SQLite
    with TestingSession() as db:
        k3 = generate_key_version(db, algorithm="AES-256-GCM", state="PREPARED")
        assert k3.version == meta["version"] + 1
        assert KeyMaterialStore().ensure_version_secret(k3.version) is not None
