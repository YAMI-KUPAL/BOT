"""
Encryption & key management for YAMI HOSTING v4.0.
Fernet/AES-128 encryption for bot files at rest.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken

from .config import DIRS, KEYRING_FILE
from .utils import _atomic_write, _load_json

# ═════════════════════════════════════════════════════════════════
# KEYRING — per-file key storage
# ═════════════════════════════════════════════════════════════════
class KeyRing:
    """Manages per-file encryption keys with in-memory + on-disk storage."""

    def __init__(self) -> None:
        self._keys: Dict[str, bytes] = {}
        self._meta: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        data = _load_json(KEYRING_FILE, {})
        self._meta = data.get("meta", {})
        # Keys are NOT stored in the JSON — they are regenerated from
        # a master key stored in env or generated once. For production,
        # use a hardware-backed key store. For this panel, keys are
        # ephemeral (regenerated from a session secret).
        self._master_key = os.environ.get("SESSION_SECRET", "").encode()
        if not self._master_key or len(self._master_key) < 32:
            self._master_key = secrets.token_bytes(32)

    def _save_meta(self) -> None:
        _atomic_write(KEYRING_FILE, {"meta": self._meta})

    def _derive_key(self, key_id: str) -> bytes:
        """Derive a deterministic Fernet key from master + key_id."""
        import hashlib
        material = self._master_key + key_id.encode()
        digest = hashlib.sha256(material).digest()
        return digest

    def store(self, key_id: str, key: bytes, meta: Dict[str, Any]) -> None:
        self._keys[key_id] = key
        self._meta[key_id] = meta
        self._save_meta()

    def fetch(self, key_id: str) -> Optional[bytes]:
        if key_id in self._keys:
            return self._keys[key_id]
        # Regenerate from master
        derived = self._derive_key(key_id)
        self._keys[key_id] = derived
        return derived

    def wipe(self, key_id: str) -> None:
        self._keys.pop(key_id, None)

    def list_ids(self) -> List[str]:
        return list(self._meta.keys())

KEYRING = KeyRing()

# ═════════════════════════════════════════════════════════════════
# ENCRYPT / DECRYPT
# ═════════════════════════════════════════════════════════════════
def encrypt_file(plain: bytes) -> Tuple[str, bytes, bytes]:
    """Encrypt plaintext bytes. Returns (key_id, key, ciphertext)."""
    key = Fernet.generate_key()
    key_id = secrets.token_hex(16)
    fernet = Fernet(key)
    cipher = fernet.encrypt(plain)
    return key_id, key, cipher

def decrypt_with(key: bytes, cipher: bytes) -> bytes:
    """Decrypt ciphertext with a Fernet key."""
    fernet = Fernet(key)
    return fernet.decrypt(cipher)

def write_encrypted(path: Path, key: bytes, plain: bytes) -> None:
    fernet = Fernet(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(fernet.encrypt(plain))

def read_encrypted(path: Path, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.decrypt(path.read_bytes())

# ═════════════════════════════════════════════════════════════════
# ENCRYPTED BOT STORAGE
# ═════════════════════════════════════════════════════════════════
import time
from .utils import safe_name, ts_iso

def store_uploaded_file(uploader_id: int, uploader_username: str,
                        filename: str, plain: bytes) -> Dict[str, Any]:
    """Encrypt + persist an uploaded file. Returns metadata."""
    safe = safe_name(filename)
    key_id, key, cipher = encrypt_file(plain)
    rel = f"{uploader_id}/{int(time.time())}_{safe}.enc"
    out = DIRS["encfiles"] / rel
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(cipher)

    meta = {
        "filename": filename,
        "uploader_id": uploader_id,
        "uploader_username": uploader_username,
        "size": len(plain),
        "uploaded": ts_iso(),
        "stored_at": str(out),
    }
    KEYRING.store(key_id, key, meta)
    return {"key_id": key_id, "path": str(out), "size": len(plain)}

def materialize_bot_files(b: Dict[str, Any]) -> None:
    """Decrypt every encrypted file for this bot into its sandbox dir."""
    from .utils import safe_path_join
    bot_dir = Path(b["dir"])
    bot_dir.mkdir(parents=True, exist_ok=True)
    files = b.get("enc_files") or []
    for f in files:
        key = KEYRING.fetch(f["key_id"])
        if not key:
            raise RuntimeError(f"missing key {f['key_id']}")
        try:
            plain = read_encrypted(Path(f["enc_path"]), key)
        except InvalidToken:
            raise RuntimeError(f"key mismatch for {f.get('filename')}")
        rel = f.get("rel_path") or f["filename"]
        rel = rel.lstrip("/")
        try:
            tgt = safe_path_join(bot_dir, rel)
        except ValueError:
            continue
        tgt.parent.mkdir(parents=True, exist_ok=True)
        tgt.write_bytes(plain)
        plain = b""
    for f in files:
        KEYRING.wipe(f["key_id"])

def encrypted_dump_for_download(b: Dict[str, Any]) -> Optional[Path]:
    """Build a zip of encrypted blobs. Not decryptable without keys."""
    import tempfile, zipfile
    from .config import BRAND_TAG
    files = b.get("enc_files") or []
    if not files:
        return None
    out = Path(tempfile.gettempdir()) / f"enc_{b['_id']}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            p = Path(f["enc_path"])
            if p.exists():
                z.write(p, arcname=f.get("rel_path") or f["filename"])
        z.writestr(
            "_README.txt",
            f"These files are encrypted with Fernet/AES-128.\n"
            f"They cannot be read without the per-file key, stored in "
            f"the private key vault of {BRAND_TAG}.\n",
        )
    return out

