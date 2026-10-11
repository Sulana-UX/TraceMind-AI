"""
Evidence Integrity and Cryptographic Hashing Module
Computes streaming SHA-256 hashes to guarantee evidence integrity without loading large files into RAM.
"""

import hashlib
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone


def compute_file_sha256(filepath: str, chunk_size: int = 65536) -> str:
    """
    Computes SHA-256 hash incrementally in 64 KB blocks.
    Memory-safe for multi-gigabyte files on 8 GB RAM machines.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_provenance_record(
    filepath: str,
    record_count: int,
    malformed_count: int,
    settings: Dict[str, Any],
    is_synthetic: bool = False
) -> Dict[str, Any]:
    """
    Creates a tamper-evident audit record capturing source file metadata and processing settings.
    """
    path = Path(filepath)
    size_bytes = path.stat().st_size if path.exists() else 0
    sha256_hash = compute_file_sha256(str(path)) if path.exists() else "N/A"

    return {
        "filename": path.name,
        "filepath": str(path.resolve()),
        "file_size_bytes": size_bytes,
        "sha256_hash": sha256_hash,
        "record_count": record_count,
        "malformed_count": malformed_count,
        "is_synthetic": is_synthetic,
        "processing_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "settings": settings,
    }
