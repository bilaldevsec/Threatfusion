from pathlib import Path

import pytest

from threatfusion.utils.checksum import sha256_file


def test_sha256_file_known_content(tmp_path: Path) -> None:
    file_path = tmp_path / "abc.txt"
    file_path.write_bytes(b"abc")

    assert sha256_file(file_path) == (
        "ba7816bf8f01cfea414140de5dae2223" "b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_file_empty_file(tmp_path: Path) -> None:
    file_path = tmp_path / "empty.txt"
    file_path.write_bytes(b"")

    assert sha256_file(file_path) == (
        "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855"
    )


def test_sha256_file_rejects_non_positive_chunk_size(tmp_path: Path) -> None:
    file_path = tmp_path / "data.bin"
    file_path.write_bytes(b"data")

    with pytest.raises(ValueError, match="chunk_size must be positive"):
        sha256_file(file_path, chunk_size=0)
