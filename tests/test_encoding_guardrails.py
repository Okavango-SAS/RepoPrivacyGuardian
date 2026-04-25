from __future__ import annotations

import subprocess
from pathlib import Path


BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
}

TEXT_EXTENSIONS_REQUIRING_NO_BOM = {
    ".py",
    ".md",
    ".toml",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
}


def _tracked_files(repo_root: Path) -> list[Path]:
    out = subprocess.check_output(
        ["git", "ls-files"],
        cwd=repo_root,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    return [repo_root / line for line in out.splitlines() if line.strip()]


def test_tracked_text_files_are_utf8_and_without_bom() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    non_utf8: list[str] = []
    with_bom: list[str] = []

    for path in _tracked_files(repo_root):
        suffix = path.suffix.lower()
        if suffix in BINARY_EXTENSIONS:
            continue

        raw = path.read_bytes()
        if b"\x00" in raw:
            continue

        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            rel = path.relative_to(repo_root).as_posix()
            non_utf8.append(f"{rel}: {exc}")
            continue

        if suffix in TEXT_EXTENSIONS_REQUIRING_NO_BOM and raw.startswith(b"\xef\xbb\xbf"):
            rel = path.relative_to(repo_root).as_posix()
            with_bom.append(rel)

        if "\ufffd" in decoded:
            rel = path.relative_to(repo_root).as_posix()
            non_utf8.append(f"{rel}: contains replacement character U+FFFD")

    assert not non_utf8, "Non-UTF8 or suspicious text detected:\n" + "\n".join(non_utf8)
    assert not with_bom, "UTF-8 BOM is not allowed in text files:\n" + "\n".join(with_bom)
