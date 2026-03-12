from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate a fresh RSA key pair.

    For a teaching project we use 2048-bit keys, which are widely supported
    and reasonably secure for practice purposes.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Serialize a private key to PEM (unencrypted PKCS8).

    In a real system you would typically encrypt the private key at rest
    with a passphrase. Here we keep it simple for teaching purposes and
    rely on file system protections.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize a public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_from_pem(data: bytes) -> rsa.RSAPrivateKey:
    """Deserialize a PEM-encoded private key."""
    return serialization.load_pem_private_key(data, password=None)


def load_public_key_from_pem(data: bytes) -> rsa.RSAPublicKey:
    """Deserialize a PEM-encoded public key."""
    return serialization.load_pem_public_key(data)

