from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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


# ---------------------------------------------------------------------------
# Phase 4 – AES session key generation and RSA-OAEP wrapping
# ---------------------------------------------------------------------------

def generate_aes_key(key_size: int = 32) -> bytes:
    """
    Generate a random AES session key.

    Default is 256-bit (32 bytes). This key will be shared between two clients
    and used for symmetric encryption in Phase 5.  It is generated fresh for
    every new conversation and never touches the server in plaintext.
    """
    return os.urandom(key_size)


def encrypt_with_rsa_public_key(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """
    Encrypt bytes using RSA-OAEP with SHA-256.

    Used by the initiator to wrap the AES session key before sending it
    through the server.  Only the holder of the corresponding private key
    can decrypt it.
    """
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_with_rsa_private_key(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """
    Decrypt bytes using RSA-OAEP with SHA-256.

    Used by the recipient to unwrap the encrypted AES session key.
    The private key never leaves the client — this operation always
    happens locally.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# Phase 5 – AES-GCM authenticated encryption for chat messages
# ---------------------------------------------------------------------------

def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt a message using AES-GCM and return (nonce, ciphertext, tag).

    AES-GCM provides both confidentiality and integrity:
    - nonce    : 96-bit random value — must be unique per message with the same key.
    - ciphertext: the encrypted message bytes.
    - tag      : 128-bit authentication tag — decryption will fail if the message
                 was tampered with in transit.

    The three components are sent separately in the JSON message so that the
    receiver can supply each one to the decryption function individually.
    """
    nonce = os.urandom(12)  # 96-bit nonce is the GCM standard recommendation
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Decrypt and verify a message using AES-GCM.

    If the ciphertext or tag has been modified (e.g. tampered in transit),
    the GCM authentication check will raise an InvalidTag exception, signalling
    that the message must be rejected.

    This guarantees both:
    - Confidentiality: only the holder of the session key can read the message.
    - Integrity: any modification is detected before the plaintext is used.
    """
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

