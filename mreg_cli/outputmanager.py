"""Output management for mreg_cli.

This is a singleton class that manages the output for the CLI. It stores the
output lines and formats them for display. It also manages the filter for the
command.
"""

from __future__ import annotations

import atexit
import datetime
import io
import json
import logging
import os
import re
from collections.abc import Iterable, Sequence
from typing import Any, Literal, NamedTuple, TypeVar, overload
from urllib.parse import urlencode, urlparse

import jq
import requests
from pydantic import BaseModel
from rich import markup
from rich.console import Console

from mreg_cli.config import MregCliConfig, OutputFormat
from mreg_cli.errorbuilder import build_error_message
from mreg_cli.exceptions import CliError, FileError
from mreg_cli.tables import AggregateResult, TableRenderable
from mreg_cli.types import Json, JsonMapping, RecordingEntry, TimeInfo

logger = logging.getLogger(__name__)

T = TypeVar("T")

DEFAULT_WIDTH = 120

console_stdout = Console(
    highlight=False,
    # account for ANSI escape codes:
    # We already set the width of the actual output in the virtual
    # console used by OutputManager, so we must set an arbitrarily large width here,
    # otherwise ANSI escape codes count towards the line width, which will mangle the output
    width=1000,
    soft_wrap=False,
)
console_stderr = Console(
    highlight=False,
    # width=None,
    soft_wrap=False,
)


class CommandFilter(NamedTuple):
    """Executed command and its filter (if any)."""

    command: str
    filter_re: re.Pattern[str] | None
    negate: bool  # only applies to regex filters
    filter_jq: Any | None


@overload
def find_char_outside_quotes(
    line: str, target_char: str, return_position: Literal[True]
) -> int: ...


@overload
def find_char_outside_quotes(
    line: str, target_char: str, return_position: Literal[False]
) -> str: ...


def find_char_outside_quotes(
    line: str, target_char: str, return_position: bool = False
) -> str | int:
    """Find a specified character in a line outside of quoted sections.

    :param line: The line of text to process.
    :param target_char: The character to find.
    :param return_position: If True, return the position of the character;
                            If False, return the line up to the character.
    :return: The position of the character or the line up to the character.
    """
    in_quotes = False
    current_quote = None

    for i, char in enumerate(line):
        if char in ["'", '"']:
            if in_quotes and char == current_quote:
                in_quotes = False
                current_quote = None
            elif not in_quotes:
                in_quotes = True
                current_quote = char
        elif char == target_char and not in_quotes:
            return i if return_position else line[:i]

    return -1 if return_position else line


def remove_comments(line: str) -> str:
    """Remove everything after "#" in line of text.

    Note: If the "#" is within a quoted string, it is not deemed to start a comment.

    :param line: The line of text to process.
    :return: The line with comments removed.
    """
    return find_char_outside_quotes(line, "#", False).rstrip(" ")


def remove_dict_key_recursive(obj: Json, key: str) -> None:
    """Remove a key from a dict or list of dicts, recursively.

    This is a destructive operation, and will modify the object in place.
    """
    if isinstance(obj, list):
        for elem in obj:
            remove_dict_key_recursive(elem, key)
        return
    elif isinstance(obj, dict):
        try:
            del obj[key]
        except KeyError:
            pass
        for other_value in obj.values():
            remove_dict_key_recursive(other_value, key)


def urlpath(url: str, params: JsonMapping) -> str:
    """Return the path and query string of a URL."""
    if params:
        url = f"{url}?{urlencode(params)}"
    up = urlparse(url)
    # Compare to empty string to avoid being tripped up by strings having
    # false-like values (0, False, etc)
    if up.query != "":
        return up.path + "?" + up.query
    else:
        return up.path


def get_console_columns() -> int:
    """Get the number of columns (width) of the console (if any).

    Returns a default width if the console size cannot be determined.
    """

    def to_int(v: str) -> int | None:
        try:
            return int(v)
        except ValueError:
            pass
        return None

    if (w := os.environ.get("COLUMNS")) and (w_int := to_int(w)):
        return w_int

    try:
        if width := os.get_terminal_size().columns:
            return width
    except OSError:  # not connected to a console
        pass

    return DEFAULT_WIDTH


class OutputManager:
    """Manages and formats output for display.

    This is a singleton class to retain context between calls. It is initiated
    and cleared in the main function of the CLI, all other calls should only
    add lines to the output via add_line(), add_formatted_line(), or
    add_formatted_line_with_source(),
    """

    _instance = None

    COMMANDS_NOT_TO_RECORD = ["recording", "quit", "exit", "source"]
    KEYS_NOT_TO_RECORD = [
        "id",
        "serialno",
        "create_date",
    ]

    def __new__(cls):
        """Create a new instance of the class, or return the existing one."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.clear()
            cls._instance.recording_clear()

        return cls._instance

    def clear(self) -> None:
        """Clear the object."""
        self._filter_re: re.Pattern[str] | None = None
        self._filter_negate: bool = False
        self._filter_jq: Any | None = None
        self._command_executed: str = ""
        self._command_issued: str = ""

        self._ok: list[str] = []  # This is typically commands that went OK but returned no content
        self._warnings: list[str] = []
        self._errors: list[str] = []

        self._api_requests: list[dict[str, Any]] = []

        self._time_started: datetime.datetime = datetime.datetime.now()
        self.console = self._get_console()

    def _get_console(self) -> Console:
        return Console(
            file=io.StringIO(),
            width=get_console_columns(),
            record=True,
            highlight=False,
        )

    @property
    def format(self) -> OutputFormat:
        conf = MregCliConfig()
        return conf.get_output_format()

    @property
    def _output(self) -> list[str]:
        """Return the output lines."""
        return self.console.export_text(styles=True).splitlines()

    def recording_clear(self) -> None:
        """Clear the recording data."""
        self._recorded_data: list[RecordingEntry] = []
        self._recording: bool = False
        self._filename: str
        self._record_timestamps: bool = True

    def record_timestamps(self, state: bool) -> None:
        """Set whether to record timestamps in the recording.

        :param state: True to record timestamps, False to not record timestamps.
        """
        self._record_timestamps = state

    def recording_start(self, filename: str) -> None:
        """Declare intent to start recording to the given filename.

        Note: The file will be overwritten if it exists.

        :param filename: The filename to record to.
        """
        # Check that we can write to the file
        try:
            with open(filename, "w") as _:
                pass
        except OSError as exc:
            raise FileError(f"Unable open recording file for writing: {filename}") from exc

        self._recording = True
        self._filename = filename

        atexit.register(self.recording_stop)
        try:
            os.remove(filename)
        except OSError:
            pass

    def recording_stop(self) -> None:
        """Stop the recording and save the recording to the file.

        Returns gracefully if recording is not active.
        """
        if not self.recording_active():
            return

        with open(self._filename, "w") as rec_file:
            json.dump(self._recorded_data, rec_file, indent=2)

        self.recording_clear()

    def recording_entry(self) -> RecordingEntry:
        """Create a recording entry."""
        now = datetime.datetime.now()
        start = self._time_started

        time: TimeInfo = {
            "timestamp": start.isoformat(sep=" ", timespec="seconds"),
            "timestamp_as_epoch": int(start.timestamp()),
            "runtime_in_ms": int((now - start).total_seconds() * 1000),
        }

        return {
            "command": self._command_executed,
            "command_filter": self._filter_re.pattern if self._filter_re else None,
            "command_filter_negate": self._filter_negate,
            "command_issued": self._command_issued,
            "ok": self._ok,
            "warning": self._warnings,
            "error": self._errors,
            "output": self._output,
            "api_requests": self._api_requests,
            "time": time if self._record_timestamps else None,
        }

    def add_warning(self, msg: str) -> None:
        """Add a warning event to the output.

        :param msg: The warning message.
        """
        self._warnings.append(msg)

    def add_error(self, msg: str) -> None:
        """Add an error event to the output.

        :param msg: The error message.
        """
        self._errors.append(msg)

    def add_ok(self, msg: str) -> None:
        """Add an OK event to the output.

        :param msg: The ok message.
        """
        self._ok.append(msg)

    def recording_active(self) -> bool:
        """Return True if recording is active."""
        return self._recording

    def recording_filename(self) -> str | None:
        """Return the filename being recorded to.

        Return gracefully if recording is not active.
        """
        if not self.recording_active():
            return None
        return self._filename

    def recording_output(self) -> None:
        """Record the output, if recording is active."""
        command = self._command_executed
        # Note that we may record commands without output as they may have
        # warnings or errors.
        if not command or not self.recording_active():
            return

        if any(command.startswith(cmd) for cmd in self.COMMANDS_NOT_TO_RECORD):
            return

        self._recorded_data.append(self.recording_entry())

    def recording_request(
        self,
        method: str,
        url: str,
        params: JsonMapping,
        data: dict[str, Any],
        result: requests.Response,
    ) -> None:
        """Record a request, if recording is active."""
        if not self.recording_active():
            return
        ret_dict: dict[str, Any] = {
            "method": method.upper(),
            "url": urlpath(url, params),
            "data": data,
            "status": result.status_code,
        }
        try:
            obj = result.json()
            for key in self.KEYS_NOT_TO_RECORD:
                remove_dict_key_recursive(obj, key)
            ret_dict["response"] = obj
        except requests.JSONDecodeError:
            s = result.content.decode("utf-8").strip()
            # Compare to empty string to avoid being tripped up by strings having
            # false-like values (0, False, etc)
            if s != "":
                ret_dict["response"] = s
        self._api_requests.append(ret_dict)

    def has_output(self) -> bool:
        """Return True if there is output to display."""
        return len(self._output) > 0

    def from_command(self, command: str) -> str:
        """Add the command that generated the output.

        Also records the command if recording is active.

        :param command: The command to add.
        :raises CliError: If the command is invalid.
        :return: The cleaned command, devoid of filters and other noise.
        """
        logger.debug(f"From command: {command}")
        self._command_issued = command.rstrip()
        flt = self.get_filter(remove_comments(self._command_issued))
        self._filter_re = flt.filter_re
        self._filter_negate = flt.negate
        self._filter_jq = flt.filter_jq
        self._command_executed = flt.command

        logger.info(f"From command (filtered): {self._command_executed}")
        return self._command_executed

    def add_line(self, line: str, *, escape: bool = False) -> None:
        """Add a line to the output.

        :param line: The line to add.
        """
        logger.debug(f"Adding line: {line}")
        if escape:
            line = markup.escape(line)
        if self._filter_re and bool(self._filter_re.search(line)) == self._filter_negate:
            # If we have a filter, and the line does not match the filter,
            # we do not add it to the output.
            logger.debug(f"Line '{line}' does not match filter '{self._filter_re.pattern}'")
            return
        self.console.print(line)

    def add_formatted_line(self, key: str, value: str, padding: int = 14) -> None:
        """Format and add a key-value pair as a line.

        :param key: The key or label.
        :param value: The value.
        :param padding: The padding for the key.
        """
        formatted_line = "{1:<{0}} {2}".format(padding, key, value)
        self.add_line(formatted_line)

    def add_formatted_line_with_source(
        self, key: str, value: str, source: str = "", padding: int = 14
    ) -> None:
        """Format and adds a key-value pair as a line with a source.

        :param key: The key or label.
        :param value: The value.
        :param source: The source of the value.
        :param padding: The padding for the key.
        """
        formatted_line = "{1:<{0}} {2:<{0}} {3}".format(padding, key, value, source)
        self.add_line(formatted_line)

    def _find_split_index(self, command: str) -> int:
        """Find the index to split the command for filtering, outside of quoted sections.

        :param command: The command string to be processed.
        :return: The index at which to split the command, or -1 if not found.
        """
        return find_char_outside_quotes(command, "|", True)

    # We want to use re.Pattern as the type here, but python 3.6 and older re-modules
    # don't have that type. So we use Any instead.
    def get_filter(self, command: str) -> CommandFilter:
        """Return the filter for the output.

        Parses the command string and extracts a filter if present, taking into
        account both single and double quoted strings to avoid incorrect
        splitting.

        :param command: The command to parse for the filter.
        :raises CliError: If the filter is invalid.
        :return: The command, the filter, and whether it is a negated filter.
        """
        negate = False
        filter_re = None
        filter_jq = None

        # JSON uses a jq filter, not a regex pattern
        if command:
            split_index = self._find_split_index(command)
            command_issued = command
            filter_str = command[split_index + 1 :].strip()
            command = command[:split_index].strip()
            if self.format == OutputFormat.JSON:
                if split_index != -1:
                    try:
                        filter_jq = jq.compile(filter_str)
                    except Exception as exc:
                        base_msg = f"Unable to compile jq filter '{filter_str}'"
                        msg = build_error_message(command_issued, base_msg)
                        raise CliError(msg) from exc
            else:
                if split_index != -1:
                    if filter_str.startswith("!"):
                        negate = True
                        filter_str = filter_str[1:].strip()

                    try:
                        filter_re = re.compile(filter_str)
                    except re.error as exc:
                        base_msg = f"Unable to compile regex '{filter_str}'"
                        msg = build_error_message(command_issued, base_msg)
                        raise CliError(msg) from exc

        return CommandFilter(
            command=command,
            filter_re=filter_re,
            negate=negate,
            filter_jq=filter_jq,
        )

    def add_formatted_table(
        self,
        headers: Iterable[str],
        keys: Iterable[str],
        data: Iterable[dict[str, Any] | BaseModel],
        indent: int = 0,
    ) -> None:
        """Format and add a table of data to the output.

        Generates a table of data from the given headers, keys, and data. The
        headers are used as the column headers, and the keys are used to
        extract the data from the dicts or Pydantic models in the data list.
        The data is formatted and added to the output.

        :param headers: Column headers for the table.
        :param keys: Keys to extract data from each item in the data list.
        :param data: A list (or any sequence) of dictionaries or Pydantic models.
        :param indent: The indentation level for the table in the output.
        """
        output_data = [item.model_dump() if isinstance(item, BaseModel) else item for item in data]

        # Prepare the format string with dynamic padding based on the longest data
        raw_format = " " * indent
        for key, header in zip(keys, headers):
            longest = max(len(header), *(len(str(d[key])) for d in output_data))
            raw_format += "{:<%d}   " % longest

        # Add headers and rows to the output
        self.add_line(raw_format.format(*headers))
        for d in output_data:
            self.add_line(raw_format.format(*[str(d[key]) for key in keys]))

    def filter_result(self, data: T) -> T | None:
        """Filter the data to include only the keys that match the filter.

        :param data: The data to filter.
        :return: The filtered data.
        """

        filter_ = self._filter_re  # pattern to match against
        negate = self._filter_negate  # remove matches

        if not filter_:
            return data

        found = False
        if isinstance(data, list):
            return list(filter(None, [self.filter_result(item) for item in data]))
        elif isinstance(data, dict):
            for k, v in list(data.items()):
                if isinstance(v, (str, int, float, bool, type(None))):
                    # We found the thing we are looking for
                    if filter_.search(str(v)):
                        found = True
                else:
                    res = self.filter_result(v)
                    if res:
                        data[k] = res
                        found = True
                    else:
                        # Remove the key if the value is empty after filtering
                        del data[k]
            if found == negate:
                # If we found something that matches the filter, and we are negating,
                # we return an empty None to indicate no match
                return None
            else:
                return data
        elif isinstance(data, str):
            if (filter_.search(data) is None) == negate:
                return (
                    data.__class__()
                )  # type narrowing on invariant (?) type, `return ""` is too narrow (apparently)
        elif isinstance(data, (int, float, bool, type(None))):
            # For simple types, we just return them as is
            return data
        return data

    def add_result(self, result: TableRenderable | Sequence[TableRenderable]) -> None:
        """Add the result of a command to the output.

        :param result: A single TableRenderable or a sequence of TableRenderables.
        """
        if self.format == OutputFormat.RICH:
            return self._render_result_table(result)
        elif self.format == OutputFormat.TEXT:
            return self._render_result_text(result)
        elif self.format == OutputFormat.JSON:
            return self._render_result_json(result)

    def _render_result_text(
        self,
        result: Sequence[TableRenderable] | TableRenderable | AggregateResult[TableRenderable],
        indent: int = 0,
    ) -> None:
        if isinstance(result, Sequence):
            result = AggregateResult(root=result)

        # Print text to a virtual console, then capture the output
        con = self._get_console()

        # Render a horizontal table for aggregates, vertical for single items
        vertical = not isinstance(result, AggregateResult)

        text_table = result.as_text(vertical=vertical, show_header=True)
        con.print(text_table)
        lines = con.file.getvalue().splitlines()

        # Add each line to the output console, which performs filtering
        for line in lines:
            self.add_line(line)

    def _render_result_table(
        self,
        row_data: Sequence[TableRenderable] | TableRenderable,
        indent: int = 0,
    ) -> None:
        """Format and add a table of data to the output.

        Generates a table of data from the given headers, keys, and data. The
        headers are used as the column headers, and the keys are used to
        extract the data from the dicts or Pydantic models in the data list.
        The data is formatted and added to the output.

        :param headers: Column headers for the table.
        :param keys: Keys to extract data from each item in the data list.
        :param data: A list (or any sequence) of dictionaries or Pydantic models.
        :param indent: The indentation level for the table in the output.
        """
        if isinstance(row_data, TableRenderable):
            # If a single TableRenderable is passed, convert it to a list
            row_data = [row_data]

        if self._filter_re:
            filtered_rows: list[TableRenderable] = []
            for row in row_data:
                res_dict = row.model_dump(mode="json")
                res_dict = self.filter_result(res_dict)
                if res_dict is None:
                    continue
                t = row.__class__.model_validate(res_dict)
                filtered_rows.append(t)
            row_data = filtered_rows

        result = AggregateResult(root=row_data)

        # Print table to the virtual console, then capture the output
        table = result.as_table()
        self.console.print(table)

    def _render_result_json(
        self,
        result: Sequence[TableRenderable] | TableRenderable,
    ) -> None:
        res: TableRenderable | AggregateResult[Any]
        if isinstance(result, TableRenderable):
            res = result
        else:
            res = AggregateResult(root=result)

        json_data = res.model_dump(mode="json")
        json_str = json.dumps(json_data, indent=2)
        if self._filter_jq:
            try:
                json_str = self._filter_jq.input_text(json_str).text()
            except Exception as exc:
                raise CliError(f"Error applying jq filter: {exc}") from exc
        self.console.print_json(json_str, indent=2)

    def filtered_output(self) -> list[str]:
        """Return the lines of output.

        If the command is set, and it has a filter, the lines will
        be filtered by the command's filter.

        Note: This filtering is not cached, so repeated calls will
        re-filter the output (to the same result, presumably).
        """
        lines = self._output
        filter_re = self._filter_re
        filter_negate = self._filter_negate

        if not filter_re:
            return lines

        if filter_negate:
            return list(line for line in lines if not filter_re.search(line))
        else:
            return list(line for line in lines if filter_re.search(line))

    # def _print_stdout(self, line: str) -> None:
    #     """Print a line to stdout, escaping markup."""
    #     console_stdout.print(line, overflow="ignore")

    # def _print_stderr(self, line: str) -> None:
    #     """Print a line to stderr, escaping markup."""
    #     console_stderr.print(line, overflow="ignore")

    def render(self) -> None:
        """Print the output to stdout, and records it if recording is active."""
        self.recording_output()

        for line in self._ok:
            console_stderr.print(f"OK: {line}")

        for line in self._output:
            console_stdout.print(line, overflow="ignore")

    def __str__(self) -> str:
        """Return the formatted output as a single string."""
        return "\n".join(self._output)
