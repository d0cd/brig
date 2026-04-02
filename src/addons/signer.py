"""
Signed Audit Log Addon for Warden.

Produces cryptographically signed log batches using Ed25519.
Each batch includes a signature that proves the log entries were
produced by this Warden instance during the stated time window.

Key management:
    - A per-session Ed25519 keypair is generated on Warden start.
    - The public key is written to /var/log/brig/audit/session_pubkey.pem.
    - Signed batches are written to /var/log/brig/audit/signed/.
    - Batches are flushed every BATCH_INTERVAL seconds or BATCH_SIZE entries.

Verification:
    To verify a signed batch:
        python3 -c "
        from addons.signer import verify_batch
        verify_batch('/var/log/brig/audit/signed/batch_001.jsonl.sig',
                     '/var/log/brig/audit/session_pubkey.pem')
        "

This addon is optional and must be explicitly enabled.
"""

import base64
import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Batch configuration.
BATCH_INTERVAL = 60  # Flush batch every 60 seconds.
BATCH_SIZE = 100     # Flush batch every 100 entries.

# Audit log directory.
AUDIT_DIR = Path("/var/log/brig/audit")
SIGNED_DIR = AUDIT_DIR / "signed"
PUBKEY_PATH = AUDIT_DIR / "session_pubkey.pem"
PRIVKEY_PATH = AUDIT_DIR / ".session_privkey.pem"

# Lock for thread-safe batch operations.
_lock = threading.Lock()

# Batch state (protected by _lock).
_batch_entries = []
_batch_start_time = None
_batch_counter = 0
_signing_key = None
_algorithm = None  # "ed25519" only.


def _ensure_dirs():
    """Create audit directories if they don't exist."""
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    SIGNED_DIR.mkdir(parents=True, exist_ok=True)
    # Restrict permissions on audit directory.
    os.chmod(str(AUDIT_DIR), 0o700)


def _generate_keypair():
    """Generate an Ed25519 keypair for this session.

    Requires the cryptography library for Ed25519. Returns False
    if cryptography is not available.
    """
    global _signing_key, _algorithm

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        _signing_key = private_key
        _algorithm = "ed25519"

        # Write public key (needed for offline verification).
        verify_key = private_key.public_key()
        pubkey_pem = verify_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _write_atomic(PUBKEY_PATH, pubkey_pem)

        # Private key stays in memory only. Ed25519 verification uses only the
        # public key, so there is no need to persist the private key to disk.
        # This prevents key theft if the container filesystem is compromised.

        return True

    except ImportError:
        # Fail hard: HMAC fallback would write shared secret to disk, which
        # violates the security model. Require 'cryptography' package for
        # Ed25519 signatures that keep the private key in memory only.
        logger.error(
            "SECURITY: 'cryptography' package is required for log signing. "
            "Install with: pip install cryptography"
        )
        return False


def _write_atomic(path: Path, data: bytes, mode: int = 0o644):
    """Write data atomically to a file."""
    tmp_path = path.with_suffix(".tmp")
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    tmp_path.rename(path)


def _sign_data(data: bytes) -> bytes:
    """Sign data with the session key."""
    if _signing_key is None:
        raise RuntimeError("Signing key not initialized")

    return _signing_key.sign(data)


def _flush_batch():
    """Flush current batch to a signed file. Caller must hold _lock."""
    global _batch_entries, _batch_start_time, _batch_counter

    if not _batch_entries:
        # Reset start time to prevent immediate re-flush on next entry.
        _batch_start_time = None
        return

    _batch_counter += 1
    batch_end_time = time.time()

    # Build batch content.
    batch = {
        "batch_id": _batch_counter,
        "start_time": _batch_start_time,
        "end_time": batch_end_time,
        "entry_count": len(_batch_entries),
        "entries": _batch_entries,
    }

    # Serialize to canonical JSON (sorted keys for reproducibility).
    batch_json = json.dumps(batch, sort_keys=True, separators=(",", ":"))
    batch_bytes = batch_json.encode("utf-8")

    # Compute content hash.
    content_hash = hashlib.sha256(batch_bytes).hexdigest()

    # Sign the batch content.
    signature = _sign_data(batch_bytes)

    # Write the batch file.
    batch_path = SIGNED_DIR / f"batch_{_batch_counter:06d}.jsonl"
    sig_path = SIGNED_DIR / f"batch_{_batch_counter:06d}.jsonl.sig"

    _write_atomic(batch_path, batch_bytes)

    # Write signature metadata.
    sig_data = json.dumps({
        "batch_id": _batch_counter,
        "content_hash": content_hash,
        "signature": base64.b64encode(signature).decode(),
        "algorithm": _algorithm,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2).encode()
    _write_atomic(sig_path, sig_data)

    # Reset batch state.
    _batch_entries = []
    _batch_start_time = None


def init():
    """Initialize the signer addon. Called once on Warden start."""
    _ensure_dirs()
    _generate_keypair()


def add_entry(entry: dict):
    """Add a log entry to the current batch (thread-safe)."""
    global _batch_start_time

    with _lock:
        if _batch_start_time is None:
            _batch_start_time = time.time()

        _batch_entries.append(entry)

        # Check flush conditions.
        if len(_batch_entries) >= BATCH_SIZE:
            _flush_batch()
        elif time.time() - _batch_start_time >= BATCH_INTERVAL:
            _flush_batch()


def _cleanup_old_batches(max_age_days: int = 7):
    """Remove batch files older than max_age_days."""
    if not SIGNED_DIR.exists():
        return
    cutoff = time.time() - (max_age_days * 86400)
    for f in SIGNED_DIR.glob("batch_*"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
        except OSError:
            pass


def flush():
    """Force flush any pending entries (thread-safe). Called on Warden stop."""
    with _lock:
        _flush_batch()
    # Clean up old batch files (keep last 7 days).
    _cleanup_old_batches()


def verify_batch(batch_path: str, pubkey_path: str) -> bool:
    """Verify a signed batch file.

    Args:
        batch_path: Path to the .jsonl batch file.
        pubkey_path: Path to the session public key.

    Returns:
        True if signature is valid, False otherwise.
    """
    batch_path = Path(batch_path)
    sig_path = batch_path.with_suffix(batch_path.suffix + ".sig")

    if not batch_path.exists() or not sig_path.exists():
        raise FileNotFoundError("Batch or signature file not found")

    batch_bytes = batch_path.read_bytes()
    sig_data = json.loads(sig_path.read_bytes())
    signature = base64.b64decode(sig_data["signature"])
    algorithm = sig_data["algorithm"]

    # Verify content hash.
    content_hash = hashlib.sha256(batch_bytes).hexdigest()
    if content_hash != sig_data["content_hash"]:
        return False

    # Only Ed25519 signatures are supported. Reject any other algorithm
    # to prevent algorithm-confusion attacks from crafted .sig files.
    if algorithm != "ed25519":
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    try:
        from cryptography.hazmat.primitives import serialization

        pubkey_pem = Path(pubkey_path).read_bytes()
        public_key = serialization.load_pem_public_key(pubkey_pem)
        public_key.verify(signature, batch_bytes)
        return True
    except Exception:
        return False
