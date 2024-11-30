"""Main entry point for mreg_cli."""

from __future__ import annotations

import argparse
import functools
import getpass
import logging

from prompt_toolkit.shortcuts import CompleteStyle, PromptSession

import mreg_cli.utilities.api as api
from mreg_cli.__about__ import __version__
from mreg_cli.cli import cli, source
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliException, LoginFailedError
from mreg_cli.outputmanager import OutputManager
from mreg_cli.prompt import get_prompt_message
from mreg_cli.types import LogLevel
from mreg_cli.utilities.api import try_token_or_login

logger = logging.getLogger(__name__)


def main():
    """Entry point for the mreg cli."""
    # Read config file first, to provide defaults
    config = MregCliConfig()

    parser = argparse.ArgumentParser(description="The MREG cli")

    parser.add_argument(
        "--version",
        help="Show version and exit.",
        action="store_true",
    )

    connect_args = parser.add_argument_group("connection settings")
    connect_args.add_argument(
        "--url",
        default=config.get_url(),
        help="use mreg server at %(metavar)s (default: %(default)s)",
        metavar="URL",
    )

    connect_args.add_argument(
        "-u",
        "--user",
        default=config.get("user", getpass.getuser()),
        help="authenticate as %(metavar)s (default: %(default)s)",
        metavar="USER",
    )

    mreg_args = parser.add_argument_group("mreg settings")
    mreg_args.add_argument(
        "-d",
        "--domain",
        default=config.get("domain", config.get_default_domain()),
        help="default %(metavar)s (default: %(default)s)",
        metavar="DOMAIN",
    )

    mreg_args.add_argument(
        "-p",
        "--prompt",
        help="default %(metavar)s), defaults to the server name if not set.",
        metavar="PROMPT",
    )

    output_args = parser.add_argument_group("output settings")
    output_args.add_argument(
        "-v",
        "--log-level",
        dest="loglevel",
        default="INFO",
        choices=LogLevel.choices(),
        help="Log level for logging.",
    )
    output_args.add_argument(
        "-l",
        "--logfile",
        dest="logfile",
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
        "command", metavar="command", nargs="*", help="Oneshot command to issue to the cli."
    )

    args = parser.parse_args()

    if args.version:
        print(f"mreg-cli {__version__}")
        raise SystemExit() from None

    config.set_cmd_config(args)

    logfile = config.get_default_logfile()
    config.start_logging(logfile, args.loglevel)

    logger.debug(f"args: {args}")

    if traffic_file := config.get("record_traffic"):
        OutputManager().recording_start(traffic_file)

    if config.get("record_traffic_without_timestamps"):
        OutputManager().record_timestamps(False)

    if config.get("user") is None:
        print("Username not set in config or as argument")
        return
    elif config.get("url") is None:
        print("mreg url not set in config or as argument")
        return

    try:
        try_token_or_login(
            str(config.get("user")),
            str(config.get("url")),
            fail_without_token=args.token_only,
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
        message=functools.partial(get_prompt_message, args, config),
        search_ignore_case=True,
        completer=cli,
        complete_while_typing=True,
        complete_style=CompleteStyle.MULTI_COLUMN,
    )

    # Welcome text for the app
    print("Type -h for help.")

    # if the --source parameter was given, read commands from the source file and then exit
    if source_file := config.get("source"):
        logger.info("Reading commands from %s", source_file)
        for command in source([source_file], bool(config.get("verbosity")), False):
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


if __name__ == "__main__":
    main()
