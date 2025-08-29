"""MREG API error handling."""

from __future__ import annotations

import logging

from pydantic import BaseModel, ValidationError
from requests import Response

logger = logging.getLogger(__name__)


def fmt_error_code(code: str) -> str:
    """Format the error code.

    :param code: The error code to format.
    :returns: The formatted error code.
    """
    return code.replace("_", " ").title()


# NOTE: BASE CLASS FOR MREGError:
# We cannot use `api.abstracts.FrozenModel` as the base class here because
# it causes an import cycle when attempting to import it from `utilities.api`,
# as `api.abstracts` already imports `utilities.api`.
# This could be solved by any of the following:
#
# 1. Inline imports of `utilities.api.get`, `utilities.api.post`, etc. in
#    model methods in `api.abstracts`
# 2. Move `FrozenModel` to a separate module, free of other imports,
#    where it can be imported from anywhere.
# 3. Accept that this is an internal model where it's fine that it's not immutable,
#    and just use `BaseModel` as the base class.
#
# We choose option 3 for now, as it's the least invasive approach.
class MREGError(BaseModel):
    """Details of an MREG error."""

    code: str
    detail: str
    attr: str | None

    def fmt_error(self) -> str:
        """Format the error message.

        :param field: The field name.
        :param messages: The list of error messages.
        :returns: A formatted error message.
        """
        msg = f"{fmt_error_code(self.code)} - {self.detail}"
        if self.attr:
            msg += f": {self.attr}"
        return msg


class MREGErrorResponse(BaseModel):
    """MREG error response."""

    type: str
    errors: list[MREGError] = []

    def as_str(self) -> str:
        """Convert the error response to a string.

        :returns: A string representation of the error response.
        """
        errors = "; ".join([error.fmt_error() for error in self.errors])
        # NOTE: could result in colon followed by no errors, but it's unlikely
        return f"{fmt_error_code(self.type)}: {errors}"

    def as_json_str(self, indent: int = 2) -> str:
        """Convert the error response to a JSON string.

        :param indent: The indentation level for the JSON string.
        :returns: A JSON string representation of the error response.
        """
        return self.model_dump_json(indent=indent)


def parse_mreg_error(resp: Response) -> MREGErrorResponse | None:
    """Parse an MREG error response.

    :param resp: The response object to parse.

    :returns: A MREGErrorResponse object or None if it cannot be parsed.
    """
    try:
        return MREGErrorResponse.model_validate_json(resp.text)
    except ValidationError:
        logger.error("Failed to parse response text '%s' from %s", resp.text, resp.url)
    return None
