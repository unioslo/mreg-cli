"""Tests for token file handling.

TODO: Add tests for the following scenarios:
    - Error cases for token read/write operations
    - Class methods behavior when called on the class itself
      vs an instance of the class
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

import pytest
from inline_snapshot import snapshot

from mreg_cli.tokenfile import TokenFile

TOKENS_PATH_ORIGINAL = TokenFile.tokens_path


TOKEN_FILE_SINGLE = """
{
    "tokens": [
        {
            "token": "exampletoken123",
            "url": "https://example.com",
            "username": "exampleuser"
        }
    ]
}
"""


TOKEN_FILE_MULTIPLE = """
{
    "tokens": [
        {
            "token": "exampletoken123",
            "url": "https://example.com",
            "username": "exampleuser"
        },
        {
            "token": "footoken456",
            "url": "https://foo.com",
            "username": "foouser"
        },
        {
            "token": "bartoken789",
            "url": "https://bar.com",
            "username": "baruser"
        }
    ]
}
"""


@pytest.fixture(autouse=True)
def reset_token_file_path() -> Iterator[None]:
    """Reset the token file path after each test."""
    yield
    TokenFile.tokens_path = TOKENS_PATH_ORIGINAL


def test_load_file_nonexistent(tmp_path: Path) -> None:
    """Load from a nonexistent tokens file."""
    tokens_path = tmp_path / "does_not_exist.json"
    assert not tokens_path.exists()
    TokenFile.tokens_path = str(tokens_path)
    tokenfile = TokenFile.load()
    assert tokenfile.tokens == []


def test_load_file_empty(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Load from an empty tokens file."""
    tokens_path = tmp_path / "empty.json"
    tokens_path.touch()
    assert tokens_path.read_text() == ""
    TokenFile.tokens_path = str(tokens_path)
    tokenfile = TokenFile.load()
    assert tokenfile.tokens == []
    assert "Failed to decode JSON" in capsys.readouterr().err


def test_load_file_invalid_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Load from a tokens file with invalid JSON."""
    tokens_path = tmp_path / "invalid.json"
    tokens_path.write_text("not json")
    assert tokens_path.read_text() == snapshot("not json")
    TokenFile.tokens_path = str(tokens_path)
    tokenfile = TokenFile.load()
    assert tokenfile.tokens == []
    assert "Failed to decode JSON" in capsys.readouterr().err


def test_load_file_invalid_tokenfile(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Load from a tokens file that is not in the correct format."""
    tokens_path = tmp_path / "invalid_format.json"

    # Contents is valid JSON, but contents are not in the correct format
    tokens_path.write_text(
        json.dumps(
            {
                "tokens": [
                    {
                        "invalid_key": 123,
                        "url": "https://example.com",
                        # missing token and username keys
                    },
                    {
                        "token": "exampletoken123",
                        "url": "https://example.com",
                        "username": "exampleuser",
                    },
                ]
            }
        )
    )
    TokenFile.tokens_path = str(tokens_path)
    tokenfile = TokenFile.load()
    assert tokenfile.tokens == []
    assert "Failed to validate tokens from token file" in capsys.readouterr().err


def test_load_file_single(tmp_path: Path) -> None:
    """Load from a tokens file with a single token."""
    tokens_path = tmp_path / "single.json"
    tokens_path.write_text(TOKEN_FILE_SINGLE)
    TokenFile.tokens_path = str(tokens_path)
    tokenfile = TokenFile.load()
    tokens = tokenfile.tokens
    assert len(tokens) == 1
    assert tokens[0].token == snapshot("exampletoken123")
    assert tokens[0].url == snapshot("https://example.com")
    assert tokens[0].username == snapshot("exampleuser")


def test_load_file_multiple(tmp_path: Path) -> None:
    """Load from a tokens file with multiple tokens."""
    tokens_path = tmp_path / "multiple.json"
    tokens_path.write_text(TOKEN_FILE_MULTIPLE)
    TokenFile.tokens_path = str(tokens_path)
    assert len(TokenFile.load().tokens) == snapshot(3)


def test_get_entry(tmp_path: Path) -> None:
    """Get a token from the token file."""
    tokens_path = tmp_path / "get_token.json"
    tokens_path.write_text(TOKEN_FILE_MULTIPLE)
    TokenFile.tokens_path = str(tokens_path)

    token = TokenFile.get_entry("exampleuser", "https://example.com")
    assert token is not None
    assert token.token == snapshot("exampletoken123")
    assert token.url == snapshot("https://example.com")
    assert token.username == snapshot("exampleuser")

    token = TokenFile.get_entry("foouser", "https://foo.com")
    assert token is not None
    assert token.token == snapshot("footoken456")
    assert token.url == snapshot("https://foo.com")
    assert token.username == snapshot("foouser")

    token = TokenFile.get_entry("baruser", "https://bar.com")
    assert token is not None
    assert token.token == snapshot("bartoken789")
    assert token.url == snapshot("https://bar.com")
    assert token.username == snapshot("baruser")

    token = TokenFile.get_entry("nonexistent", "https://example.com")
    assert token is None


def test_set_entry_existing(tmp_path: Path) -> None:
    """Set a token in the token file that already exists."""
    tokens_path = tmp_path / "set_existing.json"
    tokens_path.write_text(TOKEN_FILE_MULTIPLE)
    TokenFile.tokens_path = str(tokens_path)

    assert len(TokenFile.load().tokens) == snapshot(3)
    TokenFile.set_entry("newuser", "https://new.com", "newtoken123")
    assert len(TokenFile.load().tokens) == snapshot(4)
    token = TokenFile.get_entry("newuser", "https://new.com")
    assert token is not None
    assert token.token == snapshot("newtoken123")


@pytest.mark.parametrize("create_before", [True, False], ids=["create_before", "create_after"])
def test_set_entry_new(tmp_path: Path, create_before: bool) -> None:
    """Set a token in the token file that does not already exist."""
    tokens_path = tmp_path / "set_new.json"
    if create_before:
        tokens_path.touch()  # empty file
    TokenFile.tokens_path = str(tokens_path)

    # Write tokens to the empty file
    assert len(TokenFile.load().tokens) == snapshot(0)
    TokenFile.set_entry("newuser", "https://new.com", "newtoken123")
    assert len(TokenFile.load().tokens) == snapshot(1)
    token = TokenFile.get_entry("newuser", "https://new.com")
    assert token is not None
    assert token.token == snapshot("newtoken123")

    # Try to load the tokens from the file again
    assert len(TokenFile.load().tokens) == snapshot(1)
    token = TokenFile.get_entry("newuser", "https://new.com")
    assert token is not None
    assert token.token == snapshot("newtoken123")


@pytest.mark.parametrize("exists", [True, False], ids=["existing_tokenfile", "no_tokenfile"])
def test_set_token_fails(
    caplog: pytest.LogCaptureFixture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exists: bool
) -> None:
    """Test setting a token when the file cannot be saved."""

    def failing_save(self: TokenFile) -> None:
        raise OSError(f"Permission denied for file {Path(self.tokens_path).name}")

    monkeypatch.setattr(TokenFile, "save", failing_save)

    tokens_path = tmp_path / "set_existing.json"
    if exists:
        tokens_path.write_text(TOKEN_FILE_MULTIPLE)
    TokenFile.tokens_path = str(tokens_path)

    TokenFile.set_entry("newuser", "https://new.com", "newtoken123")

    if exists:
        assert len(caplog.record_tuples) == snapshot(1)
        record = caplog.record_tuples[0]
    else:
        assert len(caplog.record_tuples) == snapshot(2)
        record = caplog.record_tuples[1]  # [0] is the warning about the missing file

    assert record == snapshot(
        (
            "mreg_cli.tokenfile",
            40,
            "Failed to set token: OSError('Permission denied for file set_existing.json')",
        )
    )
