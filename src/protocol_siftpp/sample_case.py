"""Download/extract the selected SANS FIND EVIL sample case."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

SELECTED_CASE: dict[str, Any] = {
    "case_id": "srl-2018-base-file-memory",
    "scenario": "SRL-2018 Compromised Enterprise Network",
    "folder_path": (
        "/HACKATHON-2026/Compromised APT Attack Scenarios/"
        "SRL-2018-Compromised Enterprise Network/SRL-2018"
    ),
    "file_name": "base-file-memory.7z",
    "entry_id": "a6fba49f-a7c9-4b9f-bf10-5826a3840ce9",
    "size_bytes": 318_241_288,
    "source_url": (
        "https://sansorg.egnyte.com/dd/HhH7crTYT4JK/"
        "?entryId=a6fba49f-a7c9-4b9f-bf10-5826a3840ce9"
    ),
    "egnyte_folder": "https://sansorg.egnyte.com/fl/HhH7crTYT4JK",
    "selection_reason": (
        "Smallest directly memory-focused archive in the official compromised "
        "APT sample folder; fast enough for repeated hackathon iteration."
    ),
}

MEMORY_SUFFIXES = {".raw", ".mem", ".vmem", ".dmp", ".lime", ".bin", ".img"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download_selected_case(out_dir: Path, *, overwrite: bool = False) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / SELECTED_CASE["file_name"]
    expected_size = int(SELECTED_CASE["size_bytes"])
    if archive.exists() and not overwrite:
        if archive.stat().st_size == expected_size:
            print(f"using existing archive: {archive}")
            return archive
        raise SystemExit(
            f"{archive} exists but size is {archive.stat().st_size}, expected {expected_size}; "
            "rerun with --overwrite"
        )

    tmp = archive.with_suffix(archive.suffix + ".part")
    req = urllib.request.Request(
        SELECTED_CASE["source_url"],
        headers={"User-Agent": "Protocol-SIFT++/0.1"},
    )
    print(f"downloading {SELECTED_CASE['file_name']} ({expected_size:,} bytes)")
    started = last_report = time.monotonic()
    bytes_done = 0
    with urllib.request.urlopen(req) as resp, tmp.open("wb") as fh:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
            bytes_done += len(chunk)
            now = time.monotonic()
            if now - last_report >= 5:
                mb = bytes_done / (1024 * 1024)
                rate = mb / max(now - started, 0.001)
                print(f"  {mb:,.1f} MiB downloaded ({rate:,.1f} MiB/s)")
                last_report = now
    os.replace(tmp, archive)
    return archive


def extract_archive(archive: Path, extract_dir: Path, *, overwrite: bool = False) -> list[Path]:
    import py7zr

    extract_dir.mkdir(parents=True, exist_ok=True)
    existing = [p for p in extract_dir.rglob("*") if p.is_file()]
    if existing and not overwrite:
        print(f"using existing extracted files under: {extract_dir}")
    else:
        print(f"extracting {archive} -> {extract_dir}")
        with py7zr.SevenZipFile(archive, mode="r") as z:
            z.extractall(path=extract_dir)
    return [p for p in extract_dir.rglob("*") if p.is_file()]


def memory_candidates(paths: list[Path]) -> list[Path]:
    candidates = [p for p in paths if p.suffix.lower() in MEMORY_SUFFIXES]
    if candidates:
        return sorted(candidates, key=lambda p: p.stat().st_size, reverse=True)
    return sorted(paths, key=lambda p: p.stat().st_size, reverse=True)


def write_manifest(out_dir: Path, archive: Path, extracted: list[Path]) -> Path:
    candidates = memory_candidates(extracted)
    manifest = {
        **SELECTED_CASE,
        "archive_path": str(archive),
        "archive_size_bytes": archive.stat().st_size,
        "archive_sha256": sha256_file(archive),
        "extracted_files": [
            {"path": str(p), "size_bytes": p.stat().st_size} for p in sorted(extracted)
        ],
        "memory_candidates": [
            {"path": str(p), "size_bytes": p.stat().st_size} for p in candidates
        ],
    }
    path = out_dir / "case_manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="siftpp-download-case",
        description="Download and extract the selected SANS FIND EVIL sample case.",
    )
    parser.add_argument(
        "--out",
        default="evidence/srl-2018-base-file-memory",
        help="Output directory under ignored evidence/",
    )
    parser.add_argument("--overwrite", action="store_true", help="Replace existing download/extract")
    parser.add_argument("--no-extract", action="store_true", help="Only download the archive")
    args = parser.parse_args()

    out_dir = Path(args.out)
    archive = download_selected_case(out_dir, overwrite=args.overwrite)
    extracted: list[Path] = []
    if not args.no_extract:
        extracted = extract_archive(archive, out_dir / "extracted", overwrite=args.overwrite)
    manifest = write_manifest(out_dir, archive, extracted)

    print(f"manifest: {manifest}")
    for candidate in memory_candidates(extracted):
        print(f"candidate evidence: {candidate}")


if __name__ == "__main__":
    main()
