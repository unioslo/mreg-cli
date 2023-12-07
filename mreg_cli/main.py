"""Main entry point for the mreg cli."""
import argparse
import configparser
import getpass
import logging
from typing import Union

from prompt_toolkit import HTML
from prompt_toolkit.shortcuts import CompleteStyle, PromptSession

from . import config, log, util
from .cli import cli, source
from .outputmanager import OutputManager

logger = logging.getLogger(__name__)


def setup_logging(verbosity: Union[int, None] = None):
    """Configure logging verbosity."""
    if verbosity is None:
        root = logging.getLogger()
        root.addHandler(logging.NullHandler())
    else:
        level = config.get_verbosity(int(verbosity) - 1)
        config.configure_logging(level)


def main():
    """Entry point for the mreg cli."""
    # Read config file first, to provide defaults
    conf = {}
    configpath = config.get_config_file()
    if configpath is not None:
        cfgparser = configparser.ConfigParser()
        cfgparser.read(configpath)
        conf = dict(cfgparser["mreg"].items())

    parser = argparse.ArgumentParser(description="The MREG cli")

    connect_args = parser.add_argument_group("connection settings")
    connect_args.add_argument(
        "--url",
        default=conf.get("url", config.get_default_url()),
        help="use mreg server at %(metavar)s (default: %(default)s)",
        metavar="URL",
    )

    connect_args.add_argument(
        "-u",
        "--user",
        default=conf.get("user", getpass.getuser()),
        help="authenticate as %(metavar)s (default: %(default)s)",
        metavar="USER",
    )

    mreg_args = parser.add_argument_group("mreg settings")
    mreg_args.add_argument(
        "-d",
        "--domain",
        default=conf.get("domain", config.get_default_domain()),
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
        "--source",
        dest="source",
        help="Read commands from %(metavar)s",
        metavar="SOURCE",
    )

    args = parser.parse_args()
    setup_logging(args.verbosity)
    logger.debug(f"args: {args}")
    conf = {k: v for k, v in vars(args).items() if v}

    util.set_config(conf)
    if "logfile" in conf:
        log.logfile = conf["logfile"]

    if "record_traffic" in conf:
        OutputManager().start_recording(conf["record_traffic"])

    if "user" not in conf:
        print("Username not set in config or as argument")
        return
    elif "url" not in conf:
        print("mreg url not set in config or as argument")
        return

    try:
        util.login1(conf["user"], conf["url"])
    except (EOFError, KeyboardInterrupt):
        print("")
        raise SystemExit() from None
    if args.show_token:
        print(util.session.headers["Authorization"])

    # Must import the commands, for the side effects of creating the commands
    # when importing. Ensure that the noqa comments are updated when new
    # commands are added, otherwise the import will be removed by ruff.
    from . import dhcp  # noqa
    from . import group  # noqa
    from . import history  # noqa
    from . import host  # noqa
    from . import label  # noqa
    from . import network  # noqa
    from . import permission  # noqa
    from . import policy  # noqa
    from . import zone  # noqa

    # Define a function that returns the prompt message
    def get_prompt_message():
        """Return the prompt message."""
        manager = OutputManager()
        if manager.is_recording():
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
