import argparse
import configparser
import getpass
import logging
import shlex

from prompt_toolkit import HTML
from prompt_toolkit.shortcuts import CompleteStyle, PromptSession

from . import config, log, util, mocktraffic
from .cli import cli

logger = logging.getLogger(__name__)


def setup_logging(verbosity):
    """ configure logging if verbosity is not None """
    if verbosity is None:
        root = logging.getLogger()
        root.addHandler(logging.NullHandler())
    else:
        level = config.get_verbosity(int(verbosity) - 1)
        config.configure_logging(level)


def main():

    # Read config file first, to provide defaults
    conf = {}
    configpath = config.get_config_file()
    if configpath is not None:
        cfgparser = configparser.ConfigParser()
        cfgparser.read(configpath)
        conf = dict(cfgparser["mreg"].items())

    parser = argparse.ArgumentParser(description="The MREG cli")

    connect_args = parser.add_argument_group('connection settings')
    connect_args.add_argument(
        '--url',
        default=conf.get('url', config.get_default_url()),
        help="use mreg server at %(metavar)s (default: %(default)s)",
        metavar='URL',
    )

    connect_args.add_argument(
        '-u', '--user',
        default=conf.get('user', getpass.getuser()),
        help="authenticate as %(metavar)s (default: %(default)s)",
        metavar='USER',
    )

    mreg_args = parser.add_argument_group('mreg settings')
    mreg_args.add_argument(
        '-d', '--domain',
        default=conf.get('domain', config.get_default_domain()),
        help="default %(metavar)s (default: %(default)s)",
        metavar='DOMAIN',
    )

    mreg_args.add_argument(
        '-p', '--prompt',
        default="mreg",
        help="default %(metavar)s (default: %(default)s)",
        metavar='PROMPT',
    )

    output_args = parser.add_argument_group('output settings')
    output_args.add_argument(
        '-v', '--verbosity',
        dest='verbosity',
        action='count',
        default=None,
        help="show debug messages on stderr",
    )
    output_args.add_argument(
        '-l', '--logfile',
        dest='logfile',
        help="write log to %(metavar)s",
        metavar='LOGFILE',
    )
    output_args.add_argument(
        '--show-token',
        dest='show_token',
        action='store_true',
        help="show API token after login",
    )
    output_args.add_argument(
        '--record',
        dest='record_traffic',
        help="Record all server/client traffic to %(metavar)s",
        metavar='RECFILE',
    )
    output_args.add_argument(
        '--playback',
        dest='mock_traffic',
        help="Run commands and mock all server/client traffic with data from %(metavar)s",
        metavar='MOCKFILE',
    )

    args = parser.parse_args()
    setup_logging(args.verbosity)
    logger.debug(f'args: {args}')
    conf = {k: v for k, v in vars(args).items() if v}

    util.set_config(conf)
    if 'logfile' in conf:
        log.logfile = conf['logfile']

    m = mocktraffic.MockTraffic()
    if 'mock_traffic' in conf:
        if 'record_traffic' in conf:
            print("You can't use both the playback and record options at the same time!")
            raise SystemExit()
        m.start_playback(conf['mock_traffic'])
    elif 'record_traffic' in conf:
        m.start_recording(conf['record_traffic'])

    if m.is_playback():
        util.mregurl = "http://127.0.0.1:8000/"
        util.username = "dummyuser"
    else:
        if "user" not in conf:
            print("Username not set in config or as argument")
            return
        elif "url" not in conf:
            print("mreg url not set in config or as argument")
            return

        try:
            util.login1(conf["user"], conf["url"])
        except (EOFError, KeyboardInterrupt):
            print('')
            raise SystemExit()
        if args.show_token:
            print(util.session.headers["Authorization"])

    # Must import the commands, for the side effects of creating the commands
    # when importing.
    from . import dhcp      # noqa: F401
    from . import history   # noqa: F401
    from . import group      # noqa: F401
    from . import host      # noqa: F401
    from . import label
    from . import network   # noqa: F401
    from . import permission  # noqa: F401
    from . import policy  # noqa: F401
    from . import zone      # noqa: F401

    # session is a PromptSession object from prompt_toolkit which handles
    # some configurations of the prompt for us: the text of the prompt; the
    # completer; and other visual things.
    session = PromptSession(message=HTML(f'<b>{args.prompt}</b>> '),
                            search_ignore_case=True,
                            completer=cli,
                            complete_while_typing=True,
                            complete_style=CompleteStyle.MULTI_COLUMN)

    # Welcome text for the app
    print('Type -h for help.')

    # If playing back traffic, just run through the data and exit afterwards.
    if m.is_playback():
        while True:
            line = mocktraffic.MockTraffic().get_next_command()
            if not line:
                raise SystemExit()
            print(">",line)
            cli.parse(shlex.split(line))

    # The app runs in an infinite loop and is expected to exit using sys.exit()
    while True:
        try:
            lines = session.prompt()
        except KeyboardInterrupt:
            continue
        except EOFError:
            raise SystemExit()
        try:
            for line in lines.splitlines():
                # If recording commands, submit the command line.
                # Don't record the "source" command itself.
                if m.is_recording() and not line.lstrip().startswith("source"):
                    m.record_command(line)
                # Run the command
                cli.parse(shlex.split(line))
        except ValueError as e:
            print(e)


if __name__ == '__main__':
    main()
