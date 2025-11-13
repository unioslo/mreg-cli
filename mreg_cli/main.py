"""Main entry point for mreg_cli."""

from __future__ import annotations

import argparse
import functools
import logging

from prompt_toolkit.shortcuts import CompleteStyle, PromptSession
from rich.console import Console, Group
from rich.panel import Panel

import mreg_cli.utilities.api as api
from mreg_cli import cache
from mreg_cli.__about__ import __version__
from mreg_cli.cli import cli, source
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliException, LoginFailedError
from mreg_cli.log import MregCliLogger
from mreg_cli.outputmanager import OutputManager
from mreg_cli.prompt import get_prompt_message
from mreg_cli.types import LogLevel
from mreg_cli.utilities.api import try_token_or_login

logger = logging.getLogger(__name__)

console = Console()


def main():
    """Entry point for the mreg cli."""
    # Read config file first, to provide defaults
    try:
        config = MregCliConfig()
    except Exception as e:
        logger.error("Failed to load config: %s", e)
        config = MregCliConfig.get_default_config()

    parser = argparse.ArgumentParser(description="The MREG cli")

    parser.add_argument(
        "--version",
        help="Show version and exit.",
        action="store_true",
    )

    connect_args = parser.add_argument_group("connection settings")
    connect_args.add_argument(
        "--url",
        default=config.url,
        help="use mreg server at %(metavar)s (default: %(default)s)",
        metavar="URL",
    )

    connect_args.add_argument(
        "-u",
        "--user",
        default=config.user,
        help="authenticate as %(metavar)s (default: %(default)s)",
        metavar="USER",
    )

    connect_args.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=config.http_timeout,
        help="HTTP request timeout in seconds (default: %(default)s)",
        metavar="TIMEOUT",
    )

    mreg_args = parser.add_argument_group("mreg settings")
    mreg_args.add_argument(
        "-d",
        "--domain",
        default=config.domain,
        help="default %(metavar)s (default: %(default)s)",
        metavar="DOMAIN",
    )
    mreg_args.add_argument(
        "-p",
        "--prompt",
        help="default %(metavar)s), defaults to the server name if not set.",
        metavar="PROMPT",
    )
    mreg_args.add_argument(
        "--no-cache",
        dest="cache",
        help="Disable caching of API responses.",
        action="store_false",  # NOTE: inverted flag
        default=True,
    )
    mreg_args.add_argument(
        "--cache-ttl",
        dest="cache_ttl",
        help="Maximum time to live for cache entries in seconds.",
        type=int,
        default=300,
    )

    output_args = parser.add_argument_group("output settings")
    output_args.add_argument(
        "-v",
        "--log-level",
        dest="log_level",
        default="INFO",
        choices=LogLevel.choices(),
        help="Log level for logging.",
    )
    output_args.add_argument(
        "-l",
        "--logfile",
        dest="log_file",
        help="write log to %(metavar)s",
        metavar="LOGFILE",
    )
    output_args.add_argument(
        "--show-token",
        dest="show_token",
        action="store_true",
        help="show API token after login",
    )
    output_args.add_argument(
        "--record",
        dest="record_traffic",
        help="Record all server/client traffic to %(metavar)s",
        metavar="RECFILE",
    )
    output_args.add_argument(
        "--record-without-timestamps",
        dest="record_traffic_without_timestamps",
        action="store_true",
        help="Do not apply timestamps to the recording file",
    )
    output_args.add_argument(
        "--source",
        dest="source",
        help="Read commands from %(metavar)s",
        metavar="SOURCE",
    )

    output_args.add_argument(
        "--token-only",
        dest="token_only",
        action="store_true",
        default=False,
        help="Only attempt token login, this will avoid interactive prompts.",
    )
    output_args.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Enable verbose output for certain commands.",
    )

    output_args.add_argument(
        "command", metavar="command", nargs="*", help="Oneshot command to issue to the cli."
    )

    args = parser.parse_args()
    logger.debug(f"args: {args}")

    if args.version:
        print(f"mreg-cli {__version__}")
        raise SystemExit() from None

    config.parse_cli_args(args)
    MregCliLogger().start_logging(config.log_file, config.log_level)

    if traffic_file := config.record_traffic:
        OutputManager().recording_start(traffic_file)

    if config.record_traffic_without_timestamps:
        OutputManager().record_timestamps(False)

    if not config.user:
        print("Username not set in config or as argument")
        return
    elif not config.url:
        print("mreg url not set in config or as argument")
        return

    # Configure application
    cache.configure(config)

    try:
        try_token_or_login(
            config.user,
            config.url,
            fail_without_token=config.token_only,
        )
    except (EOFError, KeyboardInterrupt, LoginFailedError) as e:
        if isinstance(e, LoginFailedError):
            e.print_and_log()
        else:
            print(e)
        raise SystemExit() from None

    if args.show_token:
        print(api.get_session_token() or "Token not found.")
        raise SystemExit() from None

    # session is a PromptSession object from prompt_toolkit which handles
    # some configurations of the prompt for us: the text of the prompt; the
    # completer; and other visual things.
    session: PromptSession[str] = PromptSession(
        message=functools.partial(get_prompt_message, config),
        search_ignore_case=True,
        completer=cli,
        complete_while_typing=True,
        complete_style=CompleteStyle.MULTI_COLUMN,
    )

    # if the --source parameter was given, read commands from the source file and then exit
    if source_file := config.source:
        logger.info("Reading commands from %s", source_file)
        for command in source([source_file], config.verbose, False):
            cli.process_command_line(command)
        return

    # Check if we got a oneshot command. If so, execute it and exit.
    if args.command:
        cmd = " ".join(args.command)
        try:
            cli.process_command_line(cmd)
        except ValueError as e:
            print(e)

        raise SystemExit() from None

    # Welcome text for the app in interactive mode
    print_greeting(config)

    # The app runs in an infinite loop and is expected to exit using sys.exit()
    logger.debug("Entering main loop")
    while True:
        try:
            lines = session.prompt()
        except KeyboardInterrupt:
            continue
        except EOFError:
            raise SystemExit() from None
        except CliException as e:
            e.print_and_log()
            raise SystemExit() from None
        else:
            try:
                for line in lines.splitlines():
                    cli.process_command_line(line)
            except ValueError as e:
                print(e)


def print_greeting(config: MregCliConfig) -> None:
    """Print greeting message for the CLI."""
    panel = Panel(
        Group(
            "Welcome to mreg-cli",
            "[dim i]Type -h for help, <Ctrl-D> or 'exit' to quit.[/]",
            "",
            "version: " + __version__,
        ),
        expand=False,
        padding=(0, 2),
    )
    console.print(panel)
    console.print()  # blank line


if __name__ == "__main__":
    main()
