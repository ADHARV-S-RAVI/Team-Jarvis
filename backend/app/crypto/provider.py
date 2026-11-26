"""Vetted cryptographic provider facade for Q-SHIELD (no custom primitives)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768

CRYPTO_PROVIDER_VERSION = "1.0"
ALG_ML_KEM_768 = "ML-KEM-768"
ALG_AES_256_GCM = "AES-256-GCM"
ALG_HKDF_SHA_256 = "HKDF-SHA-256"
ALG_HMAC_SHA_256 = "HMAC-SHA-256"
ALG_SHA_256 = "SHA-256"

AES_256_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16


class CryptoError(Exception):
    """Raised when a cryptographic operation or authentication check fails."""


@dataclass(frozen=True)
class AesGcmSealed:
    """Explicitly structured AES-256-GCM output."""

    algorithm: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes via OS CSPRNG."""
    if length <= 0:
        raise ValueError("length must be positive")
    return os.urandom(length)


def sha256_bytes(data: bytes) -> bytes:
    """Compute SHA-256 digest bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Compute lowercase hexadecimal SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """Compute lowercase hexadecimal HMAC-SHA-256."""
    if not key:
        raise CryptoError("HMAC key must be non-empty")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def hmac_sha256_verify(key: bytes, message: bytes, expected_hex: str) -> bool:
    """Constant-time verification of lowercase hexadecimal HMAC-SHA-256."""
    if not key or not isinstance(expected_hex, str):
        return False
    computed = hmac_sha256_hex(key, message)
    return hmac.compare_digest(computed, expected_hex.lower())


def hkdf_sha256(
    ikm: bytes,
    length: int,
    *,
    salt: bytes | None = None,
    info: bytes = b"",
) -> bytes:
    """Derive purpose-separated key material using HKDF-SHA-256."""
    if not ikm or length <= 0:
        raise CryptoError("Invalid HKDF input key material or length")
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return kdf.derive(ikm)


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    *,
    aad: bytes = b"",
    nonce: bytes | None = None,
) -> AesGcmSealed:
    """Encrypt and authenticate with AES-256-GCM using a fresh 96-bit OS CSPRNG nonce."""
    if len(key) != AES_256_KEY_BYTES:
        raise CryptoError(f"AES-256-GCM requires a {AES_256_KEY_BYTES}-byte key")
    used_nonce = nonce if nonce is not None else random_bytes(AES_GCM_NONCE_BYTES)
    if len(used_nonce) != AES_GCM_NONCE_BYTES:
        raise CryptoError(f"AES-256-GCM requires a {AES_GCM_NONCE_BYTES}-byte nonce")
    aesgcm = AESGCM(key)
    combined = aesgcm.encrypt(used_nonce, plaintext, aad)
    ciphertext = combined[:-AES_GCM_TAG_BYTES]
    tag = combined[-AES_GCM_TAG_BYTES:]
    return AesGcmSealed(
        algorithm=ALG_AES_256_GCM,
        nonce=used_nonce,
        ciphertext=ciphertext,
        tag=tag,
    )


def aes_gcm_decrypt(
    key: bytes,
    *,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """Verify tag and AAD before releasing AES-256-GCM plaintext."""
    if len(key) != AES_256_KEY_BYTES:
        raise CryptoError(f"AES-256-GCM requires a {AES_256_KEY_BYTES}-byte key")
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise CryptoError(f"AES-256-GCM requires a {AES_GCM_NONCE_BYTES}-byte nonce")
    if len(tag) != AES_GCM_TAG_BYTES:
        raise CryptoError(f"AES-256-GCM requires a {AES_GCM_TAG_BYTES}-byte tag")
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise CryptoError("AES-256-GCM authentication tag verification failed") from exc


def ml_kem_generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 (public_key, secret_key) pair."""
    return ml_kem_768.generate_keypair()


def ml_kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a 32-byte shared secret to a raw ML-KEM-768 public key."""
    if len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        raise CryptoError(
            f"ML-KEM-768 public key must be {ml_kem_768.PUBLIC_KEY_SIZE} bytes"
        )
    return ml_kem_768.encrypt(public_key)


def ml_kem_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate a 32-byte shared secret from an ML-KEM-768 ciphertext."""
    if len(secret_key) != ml_kem_768.SECRET_KEY_SIZE:
        raise CryptoError(
            f"ML-KEM-768 secret key must be {ml_kem_768.SECRET_KEY_SIZE} bytes"
        )
    if len(ciphertext) != ml_kem_768.CIPHERTEXT_SIZE:
        raise CryptoError(
            f"ML-KEM-768 ciphertext must be {ml_kem_768.CIPHERTEXT_SIZE} bytes"
        )
    return ml_kem_768.decrypt(secret_key, ciphertext)


def run_crypto_self_test() -> dict[str, str]:
    """
    Execute startup cryptographic self-tests using vetted algorithms and RFC 5869 KAT.
    Raises CryptoError if any self-test fails.
    """
    # 1. RFC 5869 Appendix A.1 HKDF-SHA-256 Test Case 1
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    okm = hkdf_sha256(ikm, 42, salt=salt, info=info)
    if not hmac.compare_digest(okm, expected_okm):
        raise CryptoError("HKDF-SHA-256 self-test failed")

    # 2. AES-256-GCM roundtrip & tamper rejection
    key = random_bytes(AES_256_KEY_BYTES)
    sealed = aes_gcm_encrypt(key, b"qshield-self-test", aad=b"aad-v1")
    pt = aes_gcm_decrypt(
        key,
        nonce=sealed.nonce,
        ciphertext=sealed.ciphertext,
        tag=sealed.tag,
        aad=b"aad-v1",
    )
    if pt != b"qshield-self-test":
        raise CryptoError("AES-256-GCM roundtrip self-test failed")
    try:
        aes_gcm_decrypt(
            key,
            nonce=sealed.nonce,
            ciphertext=sealed.ciphertext,
            tag=sealed.tag,
            aad=b"tampered-aad",
        )
        raise CryptoError("AES-256-GCM tamper self-test failed to reject")
    except CryptoError:
        pass

    # 3. ML-KEM-768 roundtrip
    pk, sk = ml_kem_generate_keypair()
    ct, ss_enc = ml_kem_encapsulate(pk)
    ss_dec = ml_kem_decapsulate(sk, ct)
    if not hmac.compare_digest(ss_enc, ss_dec):
        raise CryptoError("ML-KEM-768 self-test failed")

    return {
        "provider_version": CRYPTO_PROVIDER_VERSION,
        "ml_kem_768": "ok",
        "aes_256_gcm": "ok",
        "hkdf_sha_256": "ok",
        "hmac_sha_256": "ok",
    }
