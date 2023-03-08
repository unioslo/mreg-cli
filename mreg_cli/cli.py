import argparse
import os

from prompt_toolkit import HTML
from prompt_toolkit import print_formatted_text as print
from prompt_toolkit.completion import Completer, Completion

from . import mocktraffic, util
from .exceptions import CliError, CliWarning


class CliExit(Exception):
    pass


class Flag:
    def __init__(self, name, description='', short_desc='', nargs=None,
                 default=None, type=None, choices=None, required=False,
                 metavar=None, action=None):
        self.name = name
        self.short_desc = short_desc
        self.description = description
        self.nargs = nargs
        self.default = default
        self.type = type
        self.choices = choices
        self.required = required
        self.metavar = metavar
        self.action = action


def _create_command_group(parent):
    parent_name = parent.prog.strip()

    if parent_name:
        title = 'subcommands'
    else:
        title = 'commands'

    metavar = '<command>'
    description = "Run '{}' for more details".format(
        ' '.join(word for word in (parent_name, metavar, '-h') if word))

    return parent.add_subparsers(
        title=title,
        description=description,
        metavar=metavar,
    )


class Command(Completer):
    """Command is a class which acts as a wrapper around argparse and
    prompt_toolkit.
    """

    # Used to detect an error when running commands from a source file.
    last_errno = 0

    def __init__(self, parser, flags, short_desc):
        self.parser = parser
        # sub is an object used for creating sub parser for this command. A
        # command/ArgParser can only have one of this object.
        self.sub = None

        self.short_desc = short_desc
        self.children = {}
        self.flags = {}
        for flag in flags:
            if flag.name.startswith('-'):
                self.flags[flag.name.lstrip('-')] = flag

    def add_command(self, prog, description, short_desc='', epilog=None,
                    callback=None, flags=[]):
        """
        :param flags: a list of Flag objects. NB: must be handled as read-only,
        since the default value is [].
        :return: the Command object of the new command.
        """
        if not self.sub:
            self.sub = _create_command_group(self.parser)
        parser = self.sub.add_parser(prog,
                                     description=description,
                                     epilog=epilog,
                                     help=short_desc)
        for f in flags:
            # Need to create a dict with the parameters so only used
            # parameters are sent, or else exceptions are raised. Ex: if
            # required is passed with an argument which doesn't accept the
            # required option.
            args = {
                'help': f.description,
            }
            if f.type:
                args['type'] = f.type
            if f.nargs:
                args['nargs'] = f.nargs
            if f.default:
                args['default'] = f.default
            if f.choices:
                args['choices'] = f.choices
            if f.required:
                args['required'] = f.required
            if f.metavar:
                args['metavar'] = f.metavar
            if f.action:
                args['action'] = f.action
            parser.add_argument(
                f.name,
                **args
            )
        parser.set_defaults(func=callback)

        new_cmd = Command(parser, flags, short_desc)
        self.children[prog] = new_cmd
        return new_cmd

    def parse(self, args):
        try:
            args = self.parser.parse_args(args)
            # If the command has a callback function, call it.
            if 'func' in vars(args) and args.func:
                args.func(args)

        except SystemExit as e:
            # This is a super-hacky workaround to implement a REPL app using
            # argparse; Argparse calls sys.exit when it detects an error or
            # after it prints a help msg.
            self.last_errno = e.code

        except CliWarning as e:
            print(HTML(f'<i>{e}</i>'))

        except CliError as e:
            print(HTML(f'<ansired>{e}</ansired>'))

        except CliExit:
            from sys import exit
            exit(0)

        else:
            # If no exception occurred make sure errno isn't set to an error
            # code.
            self.last_errno = 0

    def get_completions(self, document, complete_event):
        cur = document.get_word_before_cursor()
        words = document.text.strip().split(' ')
        yield from self.complete(cur, words)

    def complete(self, cur, words):
        # if line is empty suggest all sub commands
        if not words:
            for name in self.children:
                yield Completion(
                    name,
                    display_meta=self.children[name].short_desc
                )
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
                        start_position=-len(cur)
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
        if cur == '-':
            cur = ''
        # If current word doesn't start with - then it isn't a flag being typed
        elif ('-' + cur) not in words:
            return

        # complete flags which aren't already used
        for name in self.flags:
            if ('-' + name) not in words:
                if name.startswith(cur):
                    yield Completion(
                        name,
                        display_meta=self.flags[name].short_desc,
                        start_position=-len(cur)
                    )


# Top parser is the root of all the command parsers
_top_parser = argparse.ArgumentParser('')
cli = Command(_top_parser, list(), '')


def _quit(args):
    raise CliExit


# Always need a quit command
cli.add_command(
    prog='quit',
    description='Exit application.',
    short_desc='Quit',
    callback=_quit,
)

cli.add_command(
    prog='quit',
    description='Exit application.',
    short_desc='Quit',
    callback=_quit,
)

cli.add_command(
    prog='exit',
    description='Exit application.',
    short_desc='Quit',
    callback=_quit,
)

def logout(args):
    util.logout()
    raise CliExit

cli.add_command(
    prog='logout',
    description='Log out from mreg and exit. Will delete token',
    short_desc='Log out from mreg',
    callback=logout,
)


def _source(args):
    """source reads commands from one or more source files.
    Each command must be on one line and the commands must be separated with
    newlines.
    The files may contain comments. The comment symbol is #
    """
    import html
    import shlex

    m = mocktraffic.MockTraffic()

    for filename in args.files:
        if filename.startswith('~'):
            filename = os.path.expanduser(filename)
        try:
            with open(filename) as f:
                for i, l in enumerate(f):
                    # Shell commands can be called from scripts. They start with '!'
                    if l.startswith('!'):
                        os.system(l[1:])
                        continue

                    # If recording commands, submit the command line.
                    # Don't record the "source" command itself.
                    if m.is_recording() and not l.lstrip().startswith('source'):
                        m.record_command(l)

                    # With comments=True shlex will remove comments from the line
                    # when splitting. Comment symbol is #
                    s = shlex.split(l, comments=True)

                    # In verbose mode all commands are printed before execution.
                    if args.verbose and s:
                        print(HTML(f'<i>> {html.escape(l.strip())}</i>'))
                    cli.parse(s)
                    if cli.last_errno != 0:
                        print(HTML(f'<ansired><i>{filename}</i>: '
                                   f'Error on line {i + 1}</ansired>'))
                        if not args.ignore_errors:
                            return
        except FileNotFoundError:
            print(f"No such file: '{filename}'")
        except PermissionError:
            print(f"Permission denied: '{filename}'")


# Always need the source command.
cli.add_command(
    prog='source',
    description='Read and run commands from the given source files.',
    short_desc='Run commands from file(s)',
    callback=_source,
    flags=[
        Flag('files',
             description='Source files to read commands from. Commands are '
                         'separated with new lines and comments are started '
                         'with "#"',
             short_desc='File names',
             nargs='+',
             metavar='SOURCE'),
        Flag('-ignore-errors',
             description='Continue command execution on error. Default is to '
                         'stop execution on error.',
             short_desc='Stop on error.',
             action='store_true'),
        Flag('-verbose',
             description='Verbose output.',
             action='store_true'),
    ]
)
