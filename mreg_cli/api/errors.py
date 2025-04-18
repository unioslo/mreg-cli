"""Parsing of error responses from the MREG API."""

from __future__ import annotations

import logging
from typing import Union

from pydantic import BaseModel, ConfigDict, ValidationError
from requests import Response

from mreg_cli.types import get_type_adapter

logger = logging.getLogger(__name__)


class _BaseMregResponse(BaseModel):
    """Base class for errors stemming from Django Rest Framework (DRF) responses."""

    # Strict matching for model fields in subclasses
    model_config = ConfigDict(extra="forbid")

    def as_string(self) -> str:
        """Return the error as a string."""
        return ""

    def fmt_error(self, field: str, messages: list[str]) -> str:
        """Format the error message.

        :param field: The field name.
        :param messages: The list of error messages.
        :returns: A formatted error message.
        """
        return f"{field}: {', '.join(messages)}"

    def join_errors(self, errors: list[str], sep: str = "; ") -> str:
        """Join the errors into a single string.

        :param errors: The list of errors to join.
        :param sep: The separator to use between errors.
        :returns: A string with the errors joined together.
        """
        return sep.join(errors)


class DetailErrorResponse(_BaseMregResponse):
    """DRF error response model with a 'detail' key."""

    detail: str

    def as_string(self) -> str:
        """Return the error as a string."""
        return self.detail

    @classmethod
    def to_string(cls, resp: Response) -> str | None:
        """Attempt to get the detail string from the response.

        :param resp: The response object to parse.

        :returns: The detail string or None if resonse cannot be parsed.
        """
        try:
            return cls.model_validate_json(resp.text).detail
        except ValidationError:
            pass


class NonFieldErrorResponse(_BaseMregResponse):
    """MREG error response model with a 'non_field_errors' key.

    This class of error responses are typically returned for validation errors.
    <https://www.django-rest-framework.org/api-guide/exceptions/>
    """

    non_field_errors: dict[str, list[str]] = {}
    """Each key is a field name and the value is a list of error messages."""

    def as_string(self) -> str:
        """Return the error as a string."""
        errors: list[str] = []
        for field, messages in self.non_field_errors.items():
            errors.append(self.fmt_error(field, messages))
        return self.join_errors(errors)


class FieldErrorResponse(_BaseMregResponse):
    """MREG error response model where fields with errors are used as keys.

    Roughly maps to a ValidationError in DRF:
    <https://www.django-rest-framework.org/api-guide/exceptions/#validationerror>
    """

    # Match all fields in the error response
    model_config = ConfigDict(extra="allow")

    def as_string(self) -> str:
        """Return the error as a string."""
        extra = self.model_extra
        if not extra:
            return ""

        errors: list[str] = []
        for k, v in extra.items():
            if isinstance(v, list):
                errors.append(self.fmt_error(k, [str(i) for i in v]))  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
            else:
                errors.append(f"{k}: {v}")
        return self.join_errors(errors)


MREGErrorResponse = Union[
    DetailErrorResponse,
    NonFieldErrorResponse,
    # NOTE: DO NOT INSERT ANY TYPES AFTER THIS POINT!
    # FieldErrorResponse should always be specified last
    # because it matches any response with a JSON object
    FieldErrorResponse,
]


def parse_mreg_error_response(resp: Response) -> MREGErrorResponse | None:
    """Parse an MREG error response.

    :param resp: The response object to parse.

    :returns: A MREGErrorResponse object or None if it cannot be parsed.
    """
    t = get_type_adapter(MREGErrorResponse)
    try:
        return t.validate_json(resp.text)
    except ValidationError:
        logger.error("Failed to parse response text '%s' from %s", resp.text, resp.url)
    return None
