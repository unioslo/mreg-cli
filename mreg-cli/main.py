import argparse
import configparser
import shlex

from collections import ChainMap

from prompt_toolkit import HTML
from prompt_toolkit.shortcuts import CompleteStyle, PromptSession


import log
import util

from cli import cli


def main():
    parser = argparse.ArgumentParser(
        description="The MREG cli")

    connect_args = parser.add_argument_group('connection settings')
    connect_args.add_argument(
        '--url',
        help="use mreg server at %(metavar)s",
        metavar='URL',
    )

    connect_args.add_argument(
        '-u', '--user',
        help="authenticate as %(metavar)s",
        metavar='USER',
    )

    connect_args.add_argument(
        '--timeout',
        type=float,
        default=None,
        help="set connection timeout to %(metavar)s seconds"
             " (default: no timeout)",
        metavar="N",
    )

    args = parser.parse_args()
    command_line_args = {k: v for k, v in vars(args).items() if v}
    cfg = configparser.ConfigParser()
    cfg.read("cli.conf")
    config = ChainMap(command_line_args, dict(cfg["mreg"].items()))

    util.set_config(config)
    log.logfile = config["log_file"]

    if "user" not in config:
        print("Username not set in config or as argument")
        return
    elif "url" not in config:
        print("mreg url not set in config or as argument")
        return

    try:
        util.login(config["user"], config["url"])
    except (EOFError, KeyboardInterrupt):
        return
    print(util.session.headers["Authorization"])

    # Must import the commands, for the side effects of creating the commands
    # when importing.
    import dhcp
    import history
    import host
    import network
    import zone

    # session is a PromptSession object from prompt_toolkit which handles
    # some configurations of the prompt for us: the text of the prompt; the
    # completer; and other visual things.
    session = PromptSession(message=HTML('<b>mreg</b>> '),
                            search_ignore_case=True,
                            completer=cli,
                            complete_while_typing=True,
                            complete_style=CompleteStyle.MULTI_COLUMN)

    # Welcome text for the app
    print('Type -h for help.')

    # The app runs in an infinite loop and is expected to exit using sys.exit()
    while True:
        try:
            lines = session.prompt()
        except KeyboardInterrupt:
            continue
        except EOFError:
            util.logout()
            break
        try:
            for line in lines.splitlines():
                cli.parse(shlex.split(line))
        except ValueError as e:
            print(e)


main()
