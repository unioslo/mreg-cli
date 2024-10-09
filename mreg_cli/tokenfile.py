"""Token file management for mreg_cli."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional, Self

from pydantic import BaseModel, TypeAdapter, ValidationError

# The contents of the token file is:

# {
#  "tokens": [
#    { "token": "token1", "url": "url1", "username": "username1" },
#    { "token": "token2", "url": "url2", "username": "username2" }
#  ...
#  ]
# }


class Token(BaseModel):
    """A token entry in the token file."""

    token: str
    url: str
    username: str


TokenList = TypeAdapter(list[Token])


class TokenFile:
    """A class for managing tokens in a JSON file."""

    tokens_path: str = os.path.join(os.getenv("HOME", ""), ".mreg-cli_auth_token.json")

    def __init__(self, tokens: Any = None):
        """Initialize the TokenFile instance."""
        self.tokens = self._validate_tokens(tokens)

    def _validate_tokens(self, tokens: Any) -> list[Token]:
        """Convert deserialized JSON to list of Token objects."""
        if tokens:
            try:
                return TokenList.validate_python(tokens)
            except ValidationError as e:
                print(
                    f"Failed to validate tokens from token file {self.tokens_path}: {e}",
                    file=sys.stderr,
                )
        return []

    def _set_file_permissions(self, mode: int) -> None:
        """Set the file permissions for the token file."""
        try:
            os.chmod(self.tokens_path, mode)
        except PermissionError:
            print(f"Failed to set permissions on {self.tokens_path}", file=sys.stderr)
        except FileNotFoundError:
            pass

    def save(self) -> None:
        """Save tokens to a JSON file."""
        with open(self.tokens_path, "w") as file:
            json.dump({"tokens": [token.model_dump() for token in self.tokens]}, file, indent=4)
        self._set_file_permissions(0o600)

    @classmethod
    def load(cls) -> Self:
        """Load tokens from a JSON file, returning a new instance of TokenFile."""
        try:
            with open(cls.tokens_path, "r") as file:
                data = json.load(file)
                return cls(tokens=data.get("tokens"))
        except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
            if isinstance(e, json.JSONDecodeError):
                print(f"Failed to decode JSON in tokens file {cls.tokens_path}", file=sys.stderr)
            return cls(tokens=[])

    @classmethod
    def get_entry(cls, username: str, url: str) -> Optional[Token]:
        """Retrieve a token by username and URL."""
        tokens_file = cls.load()
        for token in tokens_file.tokens:
            if token.url == url and token.username == username:
                return token
        return None

    @classmethod
    def set_entry(cls, username: str, url: str, new_token: str) -> None:
        """Update or add a token based on the URL and username."""
        tokens_file = cls.load()
        for token in tokens_file.tokens:
            if token.url == url and token.username == username:
                token.token = new_token
                return tokens_file.save()
        # If not found, add a new token
        tokens_file.tokens.append(Token(token=new_token, url=url, username=username))
        tokens_file.save()
