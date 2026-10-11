"""
Unit tests for Evidence Integrity Hashing and Provenance Records.
"""

import tempfile
import os
import hashlib
from src.integrity import compute_file_sha256, generate_provenance_record


def test_compute_file_sha256():
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        content = b"LANL,Forensic,Evidence,Integrity,Test\n"
        f.write(content)
        temp_path = f.name

    try:
        calculated_hash = compute_file_sha256(temp_path)
        expected_hash = hashlib.sha256(content).hexdigest()
        assert calculated_hash == expected_hash
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_generate_provenance_record():
    with tempfile.NamedTemporaryFile("wt", delete=False, encoding="utf-8") as f:
        f.write("Line1\nLine2\n")
        temp_path = f.name

    try:
        prov = generate_provenance_record(
            filepath=temp_path,
            record_count=2,
            malformed_count=0,
            settings={"max_rows": 5000, "sample_step": 1},
            is_synthetic=True
        )
        assert prov["record_count"] == 2
        assert prov["malformed_count"] == 0
        assert prov["is_synthetic"] is True
        assert len(prov["sha256_hash"]) == 64
        assert "processing_timestamp_utc" in prov
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
