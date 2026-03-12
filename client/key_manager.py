from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa

from .crypto_utils import (
    generate_rsa_keypair,
    private_key_to_pem,
    public_key_to_pem,
    load_private_key_from_pem,
    load_public_key_from_pem,
)


class KeyManager:
    """
    Manages a client's long-term RSA key pair.

    - Keys are stored under the top-level 'keys/' directory so that
      multiple client instances (alice, bob, etc.) can reuse their
      identities across runs.
    - File naming convention:
        keys/<username>_private.pem
        keys/<username>_public.pem
    """

    def __init__(self, username: str, base_dir: str | os.PathLike | None = None) -> None:
        if base_dir is None:
            # Default to the project root's "keys" directory.
            base_dir = Path(__file__).resolve().parents[2] / "keys"

        self.username = username
        self.keys_dir = Path(base_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        self._private_path = self.keys_dir / f"{username}_private.pem"
        self._public_path = self.keys_dir / f"{username}_public.pem"

    def load_or_create_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Load an existing key pair from disk, or create and save a new one.

        Returns (private_key, public_key).
        """
        if self._private_path.exists() and self._public_path.exists():
            return self._load_keys()

        private_key, public_key = generate_rsa_keypair()
        self._save_keys(private_key, public_key)
        return private_key, public_key

    def _save_keys(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey) -> None:
        """Write the key pair to disk in PEM format."""
        self._private_path.write_bytes(private_key_to_pem(private_key))
        self._public_path.write_bytes(public_key_to_pem(public_key))

    def _load_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Load an existing key pair from disk."""
        private_pem = self._private_path.read_bytes()
        public_pem = self._public_path.read_bytes()

        private_key = load_private_key_from_pem(private_pem)
        public_key = load_public_key_from_pem(public_pem)
        return private_key, public_key

    def get_public_key_pem_str(self) -> str:
        """
        Convenience helper: return the public key as a UTF-8 PEM string.

        This is what will be sent to the server during registration.
        """
        if not self._public_path.exists():
            # Ensure keys exist.
            _, _ = self.load_or_create_keys()
        return self._public_path.read_text(encoding="utf-8")

