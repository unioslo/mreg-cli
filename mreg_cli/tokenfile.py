"""Token file management for mreg_cli."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import ClassVar, Self

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

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


class TokenFile(BaseModel):
    """A class for managing tokens in a JSON file."""

    tokens: list[Token] = []

    tokens_path: ClassVar[str] = os.path.join(os.getenv("HOME", ""), ".mreg-cli_auth_token.json")

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
            file.write(self.model_dump_json(indent=4))
        self._set_file_permissions(0o600)

    @classmethod
    def load(cls) -> Self:
        """Load tokens from a JSON file, returning a new instance of TokenFile."""
        try:
            with open(cls.tokens_path) as file:
                data = json.load(file)
                return cls.model_validate(data)
        except (FileNotFoundError, KeyError, json.JSONDecodeError, ValidationError) as e:
            msg = ""
            if isinstance(e, json.JSONDecodeError):
                msg = f"Failed to decode JSON in token file {cls.tokens_path}"
            elif isinstance(e, ValidationError):
                msg = f"Failed to validate tokens from token file {cls.tokens_path}: {e}"
            if msg:
                print(msg, file=sys.stderr)
            logger.error("Failed to load token file %r: %r", cls.tokens_path, e)
        return cls()

    @classmethod
    def get_entry(cls, username: str, url: str) -> Token | None:
        """Retrieve a token by username and URL."""
        tokens_file = cls.load()
        for token in tokens_file.tokens:
            if token.url == url and token.username == username:
                return token
        return None

    @classmethod
    def set_entry(cls, username: str, url: str, new_token: str) -> None:
        """Update or add a token based on the URL and username."""
        try:
            cls._do_set_entry(username, url, new_token)
        except OSError as e:
            logger.error("Failed to set token: %r", e)

    @classmethod
    def _do_set_entry(cls, username: str, url: str, new_token: str) -> None:
        tokens_file = cls.load()
        for token in tokens_file.tokens:
            if token.url == url and token.username == username:
                token.token = new_token
                return tokens_file.save()
        # If not found, add a new token
        tokens_file.tokens.append(Token(token=new_token, url=url, username=username))
        tokens_file.save()
