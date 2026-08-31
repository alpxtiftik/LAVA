#!/usr/bin/env python3
"""
LAVA - shared firmware path helpers
===================================
Path/extraction helpers used by parser.py, enricher.py, custom_scan.py and
ground_truth.py. Kept in one place so every stage agrees on how EMBA's long
extraction paths map to firmware-relative paths and where the extracted
filesystem lives.
"""

from __future__ import annotations

from pathlib import Path

# Common prefixes of EMBA extraction directories - we take everything after this
# marker to reduce a path to its firmware-relative form.
EXTRACT_MARKERS = [
    "squashfs_v4_le_extract/",
    "fat_extract/",
    "unblob_extracted/firmware_extract/",
    "squashfs-root/",  # binwalk's classic cpio/squashfs extraction directory
    "cpio-root/",
    "jffs2-root/",
]


def normalize_path(raw_path: str) -> str:
    """Reduces EMBA's long extraction path to a firmware-relative path."""
    for marker in EXTRACT_MARKERS:
        if marker in raw_path:
            return raw_path.split(marker, 1)[1]
    return raw_path


def find_extraction_roots(log_dir: Path) -> list[Path]:
    """Finds every '<...>extract...' directory EMBA created (there can be
    several partitions: squashfs, fat, ...). The most specific/deepest ones are
    tried first so a file is not accidentally taken from another extraction."""
    roots = [p for p in log_dir.rglob("*extract*") if p.is_dir()]
    roots.sort(key=lambda p: len(str(p)), reverse=True)
    return roots


def resolve_real_path(relative_path: str, log_dir: Path, roots: list[Path]) -> Path | None:
    """Maps the path shortened by normalize_path() (e.g. 'etc/shadow') back to
    the physical file inside the real extraction directory.
    Uses is_relative_to to block path traversal attacks."""
    if relative_path.startswith("/logs/"):
        candidate = (log_dir / relative_path[6:]).resolve()
        try:
            if candidate.is_relative_to(log_dir.resolve()) and candidate.is_file():
                return candidate
        except ValueError:
            pass

    rel = relative_path.lstrip("/")
    for root in roots:
        candidate = (root / rel).resolve()
        try:
            if candidate.is_relative_to(root.resolve()) and candidate.is_file():
                return candidate
        except ValueError:
            pass

    # Fallback: if only a file name is left, search for it inside the roots
    filename = Path(relative_path).name
    if "/" in filename or "\\" in filename:
        return None  # Prevent weird names that might bypass traversal
    for root in roots:
        for p in root.rglob(filename):
            if p.is_file():
                return p
    return None


def is_probably_binary(path: Path, sniff_bytes: int = 512) -> bool:
    """We treat files containing a null byte as binary - extracting text context
    from them is meaningless (ELF, .so, compressed files, etc.)."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sniff_bytes)
        return b"\x00" in chunk
    except OSError:
        return True
