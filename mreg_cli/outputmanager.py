"""This module contains the output management for the mreg_cli package.

This is a singleton class that manages the output for the CLI. It stores the
output lines and formats them for display. It also manages the filter for the
command.
"""

import atexit
import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, cast
from urllib.parse import urlencode, urlparse

import requests

from mreg_cli.exceptions import CliError


# These functions are for generic output usage, but can't be in util.py
# because we would get a circular import.
def find_char_outside_quotes(
    line: str, target_char: str, return_position: bool = False
) -> Union[str, int]:
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
    # Yes, this will always be a string, but linters fail to understand that.
    return cast(str, find_char_outside_quotes(line, "#", False)).rstrip(" ")


def remove_dict_key_recursive(obj: object, key: str) -> None:
    """Remove a key from a dict, recursively.

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


def urlpath(url: str, params: str) -> str:
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

from mreg_cli.exceptions import CliError


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
        "created_at",
        "updated_at",
        "serialno",
        "serialno_updated_at",
        "create_date",
    ]

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)

            # Recording related attributes. These must come first as they may
            # be encountered when calling clear(). Note that these attributes are
            # not reset between commands, which is why they are not themselves
            # manipulated in clear().
            cls._recording: bool = False
            cls._filename: str = None
            cls._recorded_data: List[str] = []

            cls._instance.clear()

        return cls._instance

    def clear(self) -> None:
        """Clears the object."""
        self._lines = []
        self._filter_re = None
        self._negate = False
        self._command = None
        self.command = None

    def start_recording(self, filename: str) -> None:
        """Declare intent to start recording to the given filename.

        Note: The file will be overwritten if it exists.

        :param filename: The filename to record to.
        """
        # Check that we can write to the file
        try:
            with open(filename, "w") as _:
                pass
        except OSError as exc:
            raise CliError("Unable open file for writing: {}".format(filename)) from exc

        self._recording = True
        self._filename = filename

        atexit.register(self.save_recording)
        try:
            os.remove(filename)
        except OSError:
            pass

    def stop_recording(self) -> None:
        """Declare intent to stop recording.

        This will delete the recorded data if it has not been saved.

        Note: This does not save the recording, use save_recording() for that.
        """
        self._recorded_data = []
        self._recording = False
        self._filename = None

    def save_recording(self) -> None:
        """Save the recording to the file.

        Returns gracefully if recording is not active.
        """
        if not self.is_recording():
            return

        with open(self._filename, "w") as rec_file:
            json.dump(self._recorded_data, rec_file, indent=2)

        self.stop_recording()

    def is_recording(self) -> bool:
        """Returns True if recording is active."""
        return self._recording

    def recording_filename(self) -> Optional[str]:
        """Returns the filename being recorded to.

        Returns gracefully if recording is not active.
        """
        if not self.is_recording():
            return None
        return self._filename

    def record_command(self, command: str) -> None:
        """Record a command, if recording is active.

        :param command: The command to record.
        """
        if not self.is_recording() or not command:
            return

        # Do not record commands starting with any of the commands in
        # COMMANDS_NOT_TO_RECORD
        if any(command.startswith(cmd) for cmd in self.COMMANDS_NOT_TO_RECORD):
            return

        # Do not record empty commands
        if command and command != "\n":
            self._recorded_data.append({"command": command})

    def record_extra_output(self, output: str) -> None:
        """Record extra output, if recording is active.

        :param output: The output to record.
        """
        if not self.is_recording() or not output:
            return

        self._recorded_data.append({"output": output})

    def record_output(self) -> None:
        """Record the output, if recording is active."""
        # Don't record if we're not recording, and don't record
        # output as the  empty output
        if not self.is_recording() or not self._recorded_data:
            return

        if not self.lines():
            return

        output = "\n".join(self.lines())
        self._recorded_data.append({"output": output})

    def record_request(
        self, method: str, url: str, params: str, data: Dict[str, Any], result: requests.Response
    ) -> None:
        if not self.is_recording():
            return
        ret_dict: Dict[str, Any] = {
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
        self._recorded_data.append(ret_dict)

    def has_output(self) -> bool:
        """Returns True if there is output to display."""
        return len(self._lines) > 0

    def from_command(self, command: str) -> str:
        """Adds the command that generated the output.

        Also records the command if recording is active.

        :param command: The command to add.
        :raises CliError: If the command is invalid.
        :return: The cleaned command, devoid of filters and other noise.
        """
        self._command, self._filter_re, self._negate = self.get_filter(command)
        self.record_command(command)
        return self._command

    def add_line(self, line: str) -> None:
        """Adds a line to the output.

        :param line: The line to add.
        """
        self._lines.append(line)

    def add_formatted_line(self, key: str, value: str, padding: int = 14) -> None:
        """Formats and adds a key-value pair as a line.

        :param key: The key or label.
        :param value: The value.
        :param padding: The padding for the key.
        """
        formatted_line = "{1:<{0}} {2}".format(padding, key, value)
        self.add_line(formatted_line)

    def add_formatted_line_with_source(
        self, key: str, value: str, source: str = "", padding: int = 14
    ) -> None:
        """Formats and adds a key-value pair as a line with a source.

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
    def get_filter(self, command: str) -> Tuple[str, Any, bool]:
        """Returns the filter for the output.

        Parses the command string and extracts a filter if present, taking into
        account both single and double quoted strings to avoid incorrect
        splitting.

        :param command: The command to parse for the filter.
        :raises CliError: If the filter is invalid.
        :return: The command, the filter, and whether it is a negated filter.
        """
        negate = False
        filter_re = None

        if command:
            split_index = self._find_split_index(command)

            if split_index != -1:
                filter_str = command[split_index + 1 :].strip()
                command = command[:split_index].strip()

                if filter_str.startswith("!"):
                    negate = True
                    filter_str = filter_str[1:].strip()

                try:
                    filter_re = re.compile(filter_str)
                except re.error as exc:
                    if "|" in filter_str:
                        raise CliError(
                            "ERROR: Command parts that contain a pipe ('|') must be quoted.",
                        ) from exc
                    else:
                        raise CliError(
                            "ERROR: Unable to compile regex '{}': {}", filter_str, exc
                        ) from exc

        return (command, filter_re, negate)

    def add_formatted_table(
        self,
        headers: Sequence[str],
        keys: Sequence[str],
        data: List[Dict[str, Any]],
        indent: int = 0,
    ) -> str:
        raw_format = " " * indent
        for key, header in zip(keys, headers):
            longest = len(header)
            for d in data:
                longest = max(longest, len(str(d[key])))
            raw_format += "{:<%d}   " % longest

        self.add_line(raw_format.format(*headers))
        for d in data:
            self.add_line(raw_format.format(*[d[key] for key in keys]))

    def lines(self) -> List[str]:
        """Return the lines of output.

        If the command is set, and it has a filter, the lines will
        be filtered by the command's filter.

        Note: This filtering is not cached, so repeated calls will
        re-filter the output (to the same result, presumably).
        """
        lines = self._lines
        filter_re = self._filter_re

        if filter_re is None:
            return lines

        if self._negate:
            return [line for line in lines if not filter_re.search(line)]

        return [line for line in lines if filter_re.search(line)]

    def render(self) -> None:
        """Prints the output to stdout, and records it if recording is active."""
        self.record_output()
        for line in self.lines():
            print(line)

    def __str__(self) -> str:
        """Returns the formatted output as a single string."""
        return "\n".join(self._lines)
