"""Tests for selected sample-case helpers."""

from __future__ import annotations

import json

from protocol_siftpp.sample_case import memory_candidates, sha256_file, write_manifest


def test_memory_candidates_prefers_memory_suffixes(tmp_path):
    txt = tmp_path / "notes.txt"
    mem = tmp_path / "image.raw"
    txt.write_text("notes", encoding="utf-8")
    mem.write_bytes(b"x" * 10)

    assert memory_candidates([txt, mem]) == [mem]


def test_write_manifest_records_archive_hash_and_candidates(tmp_path):
    archive = tmp_path / "base-file-memory.7z"
    archive.write_bytes(b"archive")
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    mem = extracted / "memory.vmem"
    mem.write_bytes(b"memory")

    manifest_path = write_manifest(tmp_path, archive, [mem])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["case_id"] == "srl-2018-base-file-memory"
    assert manifest["archive_sha256"] == sha256_file(archive)
    assert manifest["memory_candidates"][0]["path"] == str(mem)
