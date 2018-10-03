import re
import os
import cmd
import traceback
from pathlib import Path

from util import *
from commands import *
from history import history


def split_args(arg_str: str) -> typing.List[str]:
    """Splits a string of arguments on whitespaces, while preserving double quoted strings
     (without the quotes) and removing parentheses.
    """
    args = []
    word = ""
    in_quotes = False
    for c in arg_str:
        if c.isspace():
            if in_quotes:
                word += c
            elif word:
                args.append(word)
                word = ""
        elif c == "\"":
            if in_quotes:
                args.append(word)
                word = ""
                in_quotes = False
            else:
                in_quotes = True
        elif c == "(" or c == ")":
            continue
        else:
            word += c
    if in_quotes:
        cli_warning("parsing input: mismatching quotes")
    if word:
        args.append(word)
    return args


class ClientShell(cmd.Cmd):
    prompt = "mreg> "

    def __init__(self):
        super(ClientShell, self).__init__()
        self.stop_on_error = False

    #####################################################################
    #   Functions which automatically handles any CommandBase() child   #
    #####################################################################

    def command_do(self, args, command):
        assert isinstance(command, CommandBase)
        args = split_args(args)
        if len(args) < 1:
            print("missing argument(s).")
            return
        elif args[0] == "help":
            if len(args) < 2 or (len(args) == 2 and not args[1]):
                print("missing help option")
                return
            else:
                command.opt_help(args[1])
        else:
            try:
                history.start_event(" ".join(self.lastcmd.split()[:2]))
                command.method(args[0])(args[1:])
            except CliException as e:
                print(e)
                if self.stop_on_error:
                    self.stop_on_error = False
                    self.cmdqueue = []
            except Exception:
                traceback.print_exc()
                if self.stop_on_error:
                    self.stop_on_error = False
                    self.cmdqueue = []
            finally:
                history.end_event()

    def command_complete(self, text, line, begidx, indidx, command):
        assert isinstance(command, CommandBase)
        words = line.split()
        wlen = len(words)
        options = command.options()
        if wlen < 2:
            return options
        elif wlen == 2 and text:
            suggestions = []
            for opt in options:
                if text == opt[0:len(text)]:
                    suggestions.append(opt)
            return suggestions
        elif wlen == 2 and words[1] == "help":
            return options
        elif wlen == 3 and text and words[1] == "help":
            suggestions = []
            for opt in options:
                if text == opt[0:len(text)]:
                    suggestions.append(opt)
            return suggestions

    def command_help(self, command):
        assert isinstance(command, CommandBase)
        print(command.help())

    ###############################
    #   Read commands from file   #
    ###############################

    def do_source(self, args):
        """Read commands from a file. If --exit is supplied then it'll stop executing on error.
    source <file-name> [--exit]
        """
        args = args.split()
        if len(args) < 1:
            cli_warning("missing file name.")
        if "--exit" in args:
            self.stop_on_error = True
        file_path = Path(args[0])
        if not file_path.exists():
            cli_warning("\"{}\" doesn't exist.".format(file_path))
        elif file_path.is_dir():
            cli_warning("\"{}\" is a directory.".format(file_path))
        else:
            with file_path.open("r") as file:
                num = 0
                while True:
                    line = file.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    num += 1
                    line = line.split(sep='#', maxsplit=1)[0].strip()
                    if line:
                        self.cmdqueue.append(line)

    def complete_source(self, text, line, begidx, endidx):
        words = line.split()
        if len(words) < 2:
            ps = "."
        elif len(words) == 2 and not text:
            return ["--exit"]
        else:
            if re.match("^/[^/]*$", words[1]):
                ps = "/"
            else:
                tmp = words[1].rsplit(sep="/", maxsplit=1)
                ps = tmp[0] if len(tmp) > 1 else "."

        suggestions = []
        for file in Path(ps).iterdir():
            if text == file.name[0:len(text)]:
                if file.is_dir():
                    suggestions.append(file.name + "/")
                else:
                    suggestions.append(file.name)
        return suggestions

    #################################
    #   Normal cmd.Cmd functions    #
    #################################

    def do_quit(self, args):
        """Exit the mreg cli."""
        return True

    do_exit = do_quit
    do_EOF = do_quit

    def do_shell(self, args):
        """Run a normal bash command ("!" is a shortcut for "shell")."""
        os.system(args)

    def do_host(self, args):
        self.command_do(args, Host())

    def complete_host(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, Host())

    def help_host(self):
        self.command_help(Host())

    def do_subnet(self, args):
        self.command_do(args, Subnet())

    def complete_subnet(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, Subnet())

    def help_subnet(self):
        self.command_help(Subnet())

    def do_zone(self, args):
        self.command_do(args, Zone())

    def complete_zone(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, Zone())

    def help_zone(self):
        self.command_help(Zone())

    def do_history(self, args):
        self.command_do(args, History())

    def complete_history(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, History())

    def help_history(self):
        self.command_help(History())

    def do_dhcp(self, args):
        self.command_do(args, Dhcp())

    def complete_dhcp(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, Dhcp())

    def help_dhcp(self):
        self.command_help(Dhcp())


if __name__ == '__main__':
    intro = "Welcome to mreg cli. Type help or ? for help."
    while True:
        try:
            ClientShell().cmdloop(intro)
            break
        except KeyboardInterrupt:
            print("\nKeyboardInterrupt")
            intro = ""
