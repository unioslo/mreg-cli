from __future__ import annotations


def normalize_line_endings(text: str) -> str:
    r"""Normalize all line endings to `\n`."""
    return text.replace("\r\n", "\n").replace("\r", "\n")
