"""Tests basiques pour vtscanner.hashing (aucune dépendance réseau)."""

import hashlib
import tempfile
from pathlib import Path

from vtscanner.hashing import compute_hashes, human_size


def test_compute_hashes_matches_hashlib():
    content = b"contenu de test pour vtscanner"
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        hashes = compute_hashes(tmp_path)
        assert hashes["md5"] == hashlib.md5(content).hexdigest()
        assert hashes["sha1"] == hashlib.sha1(content).hexdigest()
        assert hashes["sha256"] == hashlib.sha256(content).hexdigest()
    finally:
        tmp_path.unlink()


def test_human_size():
    assert human_size(500) == "500.00 o"
    assert human_size(2048) == "2.00 Ko"
    assert human_size(1024 * 1024 * 3) == "3.00 Mo"
