# Required for python 2 because prompt_toolkit expects unicode strings
from __future__ import unicode_literals

import argparse

from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.completion import WordCompleter, Completer, CompleteEvent, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.shortcuts import PromptSession, CompleteStyle


##############################################################
#  Custom completer which knows about 'host info -name/-ip'  #
#  and 'subnet info'                                         #
##############################################################

class CliCompleter(Completer):
    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Completion:
        """get_completions is a generator which must be overridden when
        implementing a custom completer for prompt toolkit.

        get_completions only yields 'host' and/or 'subnet' and calls on
        complete_host to complete 'host info', complete_host_info to complete
        'host info -name/-ip' and complete_subnet to complete 'subnet info'
        """

        word = document.get_word_before_cursor()
        commands = ['host', 'subnet', 'quit']

        # if line is empty suggest the two main commands
        if not document.text or document.text.isspace():
            for cmd in commands:
                if cmd is 'quit':
                    yield Completion(cmd)
                else:
                    yield Completion(cmd, display_meta='Command for working with %ss' % cmd)

        # Only suggest the main commands if there's only one word on the line
        if len(document.text.split(' ')) < 2:
            for cmd in commands:
                if cmd.startswith(word) and word:
                    if cmd is 'quit':
                        yield Completion(
                            cmd,
                            start_position=-len(word)
                        )
                    else:
                        yield Completion(
                            cmd,
                            display_meta='Command for working with %ss' % cmd,
                            start_position=-len(word)
                        )

        # if the line starts with one of the main commands pass it along
        words = document.text.split(' ')
        if 'host' in words:
            for completion in self.complete_host(document, complete_event):
                yield completion
        elif 'subnet' in words:
            for completion in self.complete_subnet(document, complete_event):
                yield completion

    def complete_host(self, document, complete_event):
        words = document.text.split(' ')
        word = document.get_word_before_cursor()
        # Suggest sub command if it partially matches or there's no current word
        if 'info' not in words and 'info'.startswith(word):
            yield Completion('info',
                             start_position=-len(word),
                             display_meta='Display info about a host.')
        elif document.find_backwards('info'):
            for completion in self.complete_host_info(document, complete_event):
                yield completion

    # When dealing with flags note: prompt toolkit removes dashes and commas
    # (and maybe others) from the beginning of words when asking for word before
    # cursor. F.ex:
    #   '-na'   -> word == 'na'
    #   'uio.n' -> word == 'n'
    def complete_host_info(self, document, complete_event):
        words = document.text.split(' ')
        word = document.get_word_before_cursor()
        flags = ['name', 'ip']

        # Remove already used flags
        for flag in flags:
            if ('-' + flag) in words:
                flags.remove(flag)

        # If current word is empty then no flag is suggested
        if not word:
            return
        # If the current word is - then it is the beginning of a flag
        if word is '-':
            word = ''
        # If current word doesn't start with - then it isn't a flag being typed
        elif ('-' + word) not in words:
            return

        for flag in flags:
            if flag.startswith(word):
                yield Completion(
                    flag,
                    start_position=-len(word),
                    display_meta='One or more host %ss' % flag,
                )

    def complete_subnet(self, document, complete_event):
        words = document.text.split(' ')
        word = document.get_word_before_cursor()
        if 'info'.startswith(word) and 'info' not in words:
            yield Completion('info',
                             start_position=-len(word),
                             display_meta='Display info about a subnet.')


if __name__ == '__main__':

    ##########################################################
    #  Setup argparse with the 'host' and 'subnet' commands  #
    ##########################################################

    commands = {
        'host': argparse.ArgumentParser(
            prog='host',
            description='Do host stuff.',
        ),
        'subnet': argparse.ArgumentParser(
            prog='subnet',
            description='Do subnet stuff.',
        ),
    }

    subparser = commands['host'].add_subparsers()
    info = subparser.add_parser('info', description='Show info about host.')
    info.add_argument('-name', type=str, help='Name of a host', nargs='+', default=list())
    info.add_argument('-ip', type=str, help='Ip of a host', nargs='+', default=list())

    subparser = commands['subnet'].add_subparsers()
    info = subparser.add_parser('info', description='Show info about subnet.')
    info.add_argument('SUBNET', type=str, nargs='+', default=list())

    ##########################
    #  Read-Eval-Print-Loop  #
    ##########################

    print('The prototype supports these two commands:')
    print('\thost info [-h] [-name NAME [NAME ...]] [-ip IP [IP ...]]')
    print('\tsubnet info [-h] SUBNET [SUBNET ...]')
    print('exit with "quit"') 
    session = PromptSession(message=HTML('<b>mreg</b>> '),
                            search_ignore_case=True,
                            completer=CliCompleter(),
                            complete_while_typing=True,
                            complete_style=CompleteStyle.MULTI_COLUMN)

    # Loop until 'quit' is entered (or argparse decides to exit...)
    while True:
        line = session.prompt()
        if line is 'quit':
            break
        words = line.split(' ')
        if words[0] not in commands:
            print_formatted_text(HTML('<ansired>Unknown command "%s"</ansired>' % words[0]))
        else:
            if len(words) < 2 or words[1] != 'info':
                print_formatted_text(HTML('<ansired>Invalid sub command of "%s".</ansired>' % words[0]))
            else:
                # Create a dict of the input arguments
                args = vars(commands[words[0]].parse_args(words[1:]))
                print('Executing "%s %s" on:' % (words[0], words[1]))
                for k in args:
                    for s in args[k]:
                        print_formatted_text(HTML('\t<i>%s</i>' % s))
