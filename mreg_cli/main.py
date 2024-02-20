"""Main entry point for mreg_cli."""

import argparse
import getpass
import logging
from typing import Union

from prompt_toolkit import HTML
from prompt_toolkit.shortcuts import CompleteStyle, PromptSession

import mreg_cli.utilities.api as api
from mreg_cli.cli import cli, source
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import LoginFailedError
from mreg_cli.outputmanager import OutputManager
from mreg_cli.utilities.api import try_token_or_login

from . import log

logger = logging.getLogger(__name__)


def setup_logging(verbosity: Union[int, None] = None):
    """Configure logging verbosity."""
    if verbosity is None:
        root = logging.getLogger()
        root.addHandler(logging.NullHandler())
    else:
        config = MregCliConfig()
        level = config.get_verbosity(int(verbosity) - 1)
        config.configure_logging(level)


def main():
    """Entry point for the mreg cli."""
    # Read config file first, to provide defaults
    config = MregCliConfig()

    parser = argparse.ArgumentParser(description="The MREG cli")

    # Accept empty url as the default option for the --url parameter.
    # If the user never sets the URL we will throw a value error on
    # the initial connection attempt.
    default_url = ""
    try:
        default_url = config.get_url()
    except ValueError:
        pass

    connect_args = parser.add_argument_group("connection settings")
    connect_args.add_argument(
        "--url",
        default=default_url,
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
        default="mreg",
        help="default %(metavar)s (default: %(default)s)",
        metavar="PROMPT",
    )

    output_args = parser.add_argument_group("output settings")
    output_args.add_argument(
        "-v",
        "--verbosity",
        dest="verbosity",
        action="count",
        default=None,
        help="show debug messages on stderr",
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
    setup_logging(args.verbosity)
    logger.debug(f"args: {args}")
    conf = {k: v for k, v in vars(args).items() if v}
    config.set_cmd_config(conf)

    if "logfile" in conf:
        log.logfile = conf["logfile"]

    if "record_traffic" in conf:
        OutputManager().recording_start(conf["record_traffic"])

    if "record_traffic_without_timestamps" in conf:
        OutputManager().record_timestamps(False)

    if config.get("user") is None:
        print("Username not set in config or as argument")
        return
    elif config.get("url") is None:
        print("mreg url not set in config or as argument")
        return

    try:
        try_token_or_login(
            config.get("user"), config.get("url"), fail_without_token=args.token_only
        )

    except (EOFError, KeyboardInterrupt, LoginFailedError) as e:
        print(e)
        raise SystemExit() from None
    if args.show_token:
        print(api.session.headers["Authorization"])

    # Define a function that returns the prompt message
    def get_prompt_message():
        """Return the prompt message."""
        manager = OutputManager()
        if manager.recording_active():
            return HTML(f"<i>[>'{manager.recording_filename()}']</i> <b>{args.prompt}</b>> ")
        else:
            return HTML(f"<b>{args.prompt}</b>> ")

    # session is a PromptSession object from prompt_toolkit which handles
    # some configurations of the prompt for us: the text of the prompt; the
    # completer; and other visual things.
    session = PromptSession(
        message=get_prompt_message,
        search_ignore_case=True,
        completer=cli,
        complete_while_typing=True,
        complete_style=CompleteStyle.MULTI_COLUMN,
    )

    # Welcome text for the app
    print("Type -h for help.")

    # if the --source parameter was given, read commands from the source file and then exit
    if "source" in conf:
        for command in source([conf["source"]], "verbosity" in conf, False):
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
    while True:
        try:
            lines = session.prompt()
        except KeyboardInterrupt:
            continue
        except EOFError:
            raise SystemExit() from None
        try:
            for line in lines.splitlines():
                cli.process_command_line(line)
        except ValueError as e:
            print(e)


if __name__ == "__main__":
    main()
