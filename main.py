import argparse
import shlex
import sys
from collections import MutableMapping
from typing import List, Callable, Union

from prompt_toolkit import HTML
from prompt_toolkit import print_formatted_text as print
from prompt_toolkit.completion import Completer, CompleteEvent, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.shortcuts import CompleteStyle, PromptSession


class Flag:
    def __init__(self, name, description='', nargs=None, default=None,
                 type=str, choices=None, required=False, metavar=None):
        self.name = name
        self.description = description
        self.nargs = nargs
        self.default = default
        self.type = type
        self.choices = choices
        self.required = required
        self.metavar = metavar


class Command(Completer):
    """Command is a class which acts as a wrapper around argparse and
    prompt_toolkit.
    """

    def __init__(self, parser: argparse.ArgumentParser, flags: List[Flag]):
        self.parser = parser

        self.children = {}
        self.flags = {}
        for flag in flags:
            if flag.name.startswith('-'):
                self.flags[flag.name.lstrip('-')] = flag

    def add_command(self, prog: str, description: str, callback,
                    flags: List[Flag] = []):
        """
        :param flags: a list of Flag objects. NB: must be handled as read-only,
        since the default value is [].
        :return: the Command object of the new command.
        """
        sub = self.parser.add_subparsers()
        parser = sub.add_parser(prog, description=description)
        for f in flags:
            parser.add_argument(
                f.name,
                nargs=f.nargs,
                default=f.default,
                type=f.type,
                choices=f.choices,
                required=f.required,
                metavar=f.metavar,
            )
        parser.set_defaults(func=callback)

        new_cmd = Command(parser, flags)
        self.children[prog] = new_cmd
        return new_cmd

    def parse(self, args: List[str]):
        try:
            args = self.parser.parse_args(args)
            args.func(args)
        except SystemExit as n:
            # Only allow the application to terminate with the 0 exit code since
            # argparse calls sys.exit(2) on parsing error, which needs to be
            # caught.
            if n.code == 0:
                sys.exit(0)

    def get_completions(self, document: Document,
                        complete_event: CompleteEvent):
        cur = document.get_word_before_cursor()
        words = document.text.strip().split(' ')
        for c in self.complete(cur, words):
            yield c

    def complete(self, cur, words):
        # if line is empty suggest all sub commands
        if not words:
            for name in self.children:
                yield Completion(
                    name,
                    display_meta=self.children[name].parser.description
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
                        display_meta=self.children[name].parser.description,
                        start_position=-len(name)
                    )

        # if the line starts with one of the sub commands, pass it along
        if words[0] in self.children:
            for c in self.children[words[0]].complete(cur, words[1:]):
                yield c
            return

        # If none of the above then check if some of the flags match

        # If current word is empty then no flag is suggested
        if not cur:
            return
        # If the current word is - then it is the beginning of a flag
        if cur is '-':
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
                        display_meta=self.flags[name].description,
                        start_position=-len(cur)
                    )


_top_parser = argparse.ArgumentParser('')
cli = Command(_top_parser, list())

if __name__ == '__main__':
    session = PromptSession(message=HTML('<b>mreg</b>> '),
                            search_ignore_case=True,
                            completer=cli,
                            complete_while_typing=True,
                            complete_style=CompleteStyle.MULTI_COLUMN)

    cli.add_command(
        prog='quit',
        description='Exit application.',
        callback=lambda a: sys.exit(0) if not a.h else None,
    )

    while True:
        line = session.prompt()

        # shlex is a lexical analyser which handles quotes automatically, and
        # will allow handling of comments in input if necessary
        cli.parse(shlex.split(line))
