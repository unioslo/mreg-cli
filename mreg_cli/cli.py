"""Command line interface for mreg.

This file contains the main CLI class and the top level parser.
"""

import argparse
import html
import os
import shlex
import sys
from typing import Any, Callable, Generator, List, Union

from prompt_toolkit import HTML, document, print_formatted_text
from prompt_toolkit.completion import CompleteEvent, Completer, Completion

from . import util
from .exceptions import CliError, CliWarning
from .outputmanager import OutputManager, remove_comments


class CliExit(Exception):
    """Exception used to exit the CLI."""

    pass


class Flag:
    """Class for flag information available to commands in the CLI."""

    def __init__(
        self,
        name: str,
        description: str = "",
        short_desc: str = "",
        nargs: int = None,
        default: Any = None,
        flag_type: Any = None,
        choices: List[str] = None,
        required: bool = False,
        metavar: str = None,
        action: str = None,
    ):
        """Initialize a Flag object."""
        self.name = name
        self.short_desc = short_desc
        self.description = description
        self.nargs = nargs
        self.default = default
        self.type = flag_type
        self.choices = choices
        self.required = required
        self.metavar = metavar
        self.action = action


def _create_command_group(parent: argparse.ArgumentParser):
    """Create a sub parser for a command."""
    parent_name = parent.prog.strip()

    if parent_name:
        title = "subcommands"
    else:
        title = "commands"

    metavar = "<command>"
    description = "Run '{}' for more details".format(
        " ".join(word for word in (parent_name, metavar, "-h") if word)
    )

    return parent.add_subparsers(
        title=title,
        description=description,
        metavar=metavar,
    )


class Command(Completer):
    """Command class for the CLI.

    Wrapper around argparse.ArgumentParser and prompt_toolkit.
    """

    # Used to detect an error when running commands from a source file.
    last_errno = 0

    def __init__(self, parser: argparse.ArgumentParser, flags: List[Flag], short_desc: str):
        """Initialize a Command object."""
        self.parser = parser
        # sub is an object used for creating sub parser for this command. A
        # command/ArgParser can only have one of this object.
        self.sub = None

        self.short_desc = short_desc
        self.children = {}
        self.flags = {}
        for flag in flags:
            if flag.name.startswith("-"):
                self.flags[flag.name.lstrip("-")] = flag

    def add_command(
        self,
        prog: str,
        description: str,
        short_desc: str = "",
        epilog: str = None,
        callback: Callable[[argparse.ArgumentParser], None] = None,
        flags: Union[List[Flag], None] = None,
    ):
        """Add a command to the current parser.

        :param flags: a list of Flag objects. NB: must be handled as read-only,
        since the default value is [].
        :return: the Command object of the new command.
        """
        if flags is None:
            flags = []
        if not self.sub:
            self.sub = _create_command_group(self.parser)
        parser = self.sub.add_parser(prog, description=description, epilog=epilog, help=short_desc)
        for f in flags:
            # Need to create a dict with the parameters so only used
            # parameters are sent, or else exceptions are raised. Ex: if
            # required is passed with an argument which doesn't accept the
            # required option.
            args = {
                "help": f.description,
            }
            if f.type:
                args["type"] = f.type
            if f.nargs:
                args["nargs"] = f.nargs
            if f.default:
                args["default"] = f.default
            if f.choices:
                args["choices"] = f.choices
            if f.required:
                args["required"] = f.required
            if f.metavar:
                args["metavar"] = f.metavar
            if f.action:
                args["action"] = f.action
            parser.add_argument(f.name, **args)
        parser.set_defaults(func=callback)

        new_cmd = Command(parser, flags, short_desc)
        self.children[prog] = new_cmd
        return new_cmd

    def parse(self, command: str) -> None:
        """Parse and execute a command."""
        args = shlex.split(command, comments=True)

        try:
            args = self.parser.parse_args(args)
            # If the command has a callback function, call it.
            if "func" in vars(args) and args.func:
                args.func(args)

        except SystemExit as e:
            # This is a super-hacky workaround to implement a REPL app using
            # argparse; Argparse calls sys.exit when it detects an error or
            # after it prints a help msg.
            self.last_errno = e.code

        except (CliWarning, CliError) as exc:
            exc.print_self()

        except CliExit:
            # If we have active recordings going on, save them before exiting
            OutputManager().save_recording()
            sys.exit(0)

        else:
            # If no exception occurred make sure errno isn't set to an error
            # code.
            self.last_errno = 0

    def get_completions(
        self, document: document.Document, complete_event: CompleteEvent
    ) -> Generator[Union[Completion, Any], Any, None]:
        """Prepare completions for the current command.

        :param document: The current document.
        :param complete_event: The current complete event.

        :yields: Completions for the current command.
        """
        cur = document.get_word_before_cursor()
        words = document.text.strip().split(" ")
        yield from self.complete(cur, words)

    def complete(self, cur: str, words: str) -> Generator[Union[Completion, Any], Any, None]:
        """Generate completions during typing.

        :param cur: The current word.
        :param words: The current line split into words.
        """
        # if line is empty suggest all sub commands
        if not words:
            for name in self.children:
                yield Completion(name, display_meta=self.children[name].short_desc)
            return

        # only suggest sub commands if there's only one word on the line.
        # this behavior might cause a sub command to be suggested when typing
        # an unflagged argument, but it avoids suggestion of sub commands
        # purely based on current word, which would cause suggestions of sub
        # commands at any time when typing a matching word.
        # NOTE: must not return at end of block or else there'll be a bug when
        # the first (and only) word is a flag.
        if len(words) < 2:
            for name in self.children:
                if name.startswith(cur) and cur:
                    yield Completion(
                        name,
                        display_meta=self.children[name].short_desc,
                        start_position=-len(cur),
                    )

        # if the line starts with one of the sub commands, pass it along
        if words[0] in self.children:
            yield from self.children[words[0]].complete(cur, words[1:])
            return

        # If none of the above then check if some of the flags match

        # If current word is empty then no flag is suggested
        if not cur:
            return
        # If the current word is - then it is the beginning of a flag
        if cur == "-":
            cur = ""
        # If current word doesn't start with - then it isn't a flag being typed
        elif ("-" + cur) not in words:
            return

        # complete flags which aren't already used
        for name in self.flags:
            if ("-" + name) not in words:
                if name.startswith(cur):
                    yield Completion(
                        name,
                        display_meta=self.flags[name].short_desc,
                        start_position=-len(cur),
                    )

    def process_command_line(self, line: str) -> None:
        """Process a line containing a command."""
        line = remove_comments(line)
        # OutputManager is a singleton class so we
        # need to clear it before each command.
        output = OutputManager()
        output.clear()
        # Set the command that generated the output
        # Also remove filters and other noise.
        cmd = output.from_command(line)
        # Run the command
        cli.parse(cmd)
        # Render the output
        output.render()


# Top parser is the root of all the command parsers
_top_parser = argparse.ArgumentParser("")
cli = Command(_top_parser, list(), "")


def _quit(args: argparse.Namespace):
    raise CliExit


def _start_recording(args: argparse.Namespace) -> None:
    """Start recording commands and output to the given file."""
    if not args.filename:
        raise CliError("No filename given.")

    OutputManager().start_recording(args.filename)


def _stop_recording(args: argparse.Namespace):
    """Stop recording commands and output to the given file."""
    OutputManager().save_recording()


# Always need a quit command
cli.add_command(
    prog="quit",
    description="Exit application.",
    short_desc="Quit",
    callback=_quit,
)

cli.add_command(
    prog="exit",
    description="Exit application.",
    short_desc="Quit",
    callback=_quit,
)


def logout(args: argparse.Namespace):
    """Log out from mreg and exit. Will delete token."""
    util.logout()
    raise CliExit


cli.add_command(
    prog="logout",
    description="Log out from mreg and exit. Will delete token",
    short_desc="Log out from mreg",
    callback=logout,
)

recordings = cli.add_command(
    prog="recording",
    description="Recording related commands.",
    short_desc="Recording related commands",
)

recordings.add_command(
    prog="start",
    description="Start recording commands to a file.",
    short_desc="Start recording",
    callback=_start_recording,
    flags=[
        Flag(
            "filename",
            description="The filename to record to.",
            short_desc="Filename",
            metavar="filename",
        )
    ],
)

recordings.add_command(
    prog="stop",
    description="Stop recording commands and output to the given file.",
    short_desc="Stop recording",
    callback=_stop_recording,
)


def source(files: List[str], ignore_errors: bool, verbose: bool) -> Generator[str, None, None]:
    """Read commands from one or more source files and yield them.

    :param files: List of file paths to read commands from.
    :param ignore_errors: If True, continue on errors.
    :param verbose: If True, print commands before execution.

    :yields: Command lines from the files.
    """
    for filename in files:
        if filename.startswith("~"):
            filename = os.path.expanduser(filename)
        try:
            with open(filename) as f:
                for i, line in enumerate(f):
                    # Shell commands can be called from scripts. They start with '!'
                    if line.startswith("!"):
                        os.system(line[1:])
                        continue

                    if verbose:
                        print_formatted_text(HTML(f"<i>> {html.escape(line.strip())}</i>"))

                    yield line

                    if cli.last_errno != 0:
                        print_formatted_text(
                            HTML(
                                (
                                    f"<ansired><i>{filename}</i>: "
                                    f"Error on line {i + 1}</ansired>"
                                )
                            )
                        )
                        OutputManager().record_extra_output(f"{filename}: Error on line {i + 1}")
                        if not ignore_errors:
                            return
        except FileNotFoundError:
            print_formatted_text(f"No such file: '{filename}'")
        except PermissionError:
            print_formatted_text(f"Permission denied: '{filename}'")


def _source(args: argparse.Namespace):
    """Source command for the CLI.

    :param args: The arguments passed to the command.
    """
    for command in source(args.files, args.ignore_errors, args.verbose):
        # Process each command here as needed, similar to the main loop
        print(f"Processing command: {command}")
        cli.process_command_line(command)


# Always need the source command.
cli.add_command(
    prog="source",
    description="Read and run commands from the given source files.",
    short_desc="Run commands from file(s)",
    callback=_source,
    flags=[
        Flag(
            "files",
            description=(
                "Source files to read commands from. Commands are "
                "separated with new lines and comments are started "
                'with "#"'
            ),
            short_desc="File names",
            nargs="+",
            metavar="SOURCE",
        ),
        Flag(
            "-ignore-errors",
            description=(
                "Continue command execution on error. Default is to stop execution on error."
            ),
            short_desc="Stop on error.",
            action="store_true",
        ),
        Flag("-verbose", description="Verbose output.", action="store_true"),
    ],
)
