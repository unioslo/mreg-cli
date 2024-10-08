"""Token file management for mreg_cli."""

from __future__ import annotations

import json
import os
import sys
from typing import Optional

from pydantic import BaseModel

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


class TokenFile:
    """A class for managing tokens in a JSON file."""

    tokens_path: str = os.path.join(os.getenv("HOME", ""), ".mreg-cli_auth_token.json")

    def __init__(self, tokens: Optional[list[dict[str, str]]] = None):
        """Initialize the TokenFile instance."""
        self.tokens = [Token(**token) for token in tokens] if tokens else []

    @classmethod
    def _load_tokens(cls) -> "TokenFile":
        """Load tokens from a JSON file, returning a new instance of TokenFile."""
        try:
            with open(cls.tokens_path, "r") as file:
                data = json.load(file)
                return TokenFile(tokens=data["tokens"])
        except (FileNotFoundError, KeyError):
            return TokenFile(tokens=[])

    @classmethod
    def _set_file_permissions(cls, mode: int) -> None:
        """Set the file permissions for the token file."""
        try:
            os.chmod(cls.tokens_path, mode)
        except PermissionError:
            print("Failed to set permissions on " + cls.tokens_path, file=sys.stderr)
        except FileNotFoundError:
            pass

    @classmethod
    def _save_tokens(cls, tokens: "TokenFile") -> None:
        """Save tokens to a JSON file."""
        with open(cls.tokens_path, "w") as file:
            json.dump({"tokens": [token.model_dump() for token in tokens.tokens]}, file, indent=4)

        cls._set_file_permissions(0o600)

    @classmethod
    def get_entry(cls, username: str, url: str) -> Optional[Token]:
        """Retrieve a token by username and URL."""
        tokens_file = cls._load_tokens()
        for token in tokens_file.tokens:
            if token.url == url and token.username == username:
                return token
        return None

    @classmethod
    def set_entry(cls, username: str, url: str, new_token: str) -> None:
        """Update or add a token based on the URL and username."""
        tokens_file = cls._load_tokens()
        for token in tokens_file.tokens:
            if token.url == url and token.username == username:
                token.token = new_token
                cls._save_tokens(tokens_file)
                return

        # If not found, add a new token
        tokens_file.tokens.append(Token(token=new_token, url=url, username=username))
        cls._save_tokens(tokens_file)
