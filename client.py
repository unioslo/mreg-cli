import re
import os
import cmd
import traceback
from pathlib import Path

from util import *
from commands import *
from history import history


def split_args(arg_str: str) -> typing.List[str]:
    """Splits a string of arguments on whitespaces, while preserving double quoted string and
    removing pparentheses
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
    intro = "Welcome to mreg cli. Type help or ? for help."
    prompt = "mreg> "

    #####################################################################
    #   Functions which automatically handles any CommandBase() child   #
    #####################################################################

    def command_do(self, args, command):
        assert isinstance(command, CommandBase)
        # TODO ARGS: Split the arguments better. Do not split strings inside double quotes
        args = split_args(args)
        if len(args) < 1:
            print("missing argument(s).")
            return
        elif args[0] == "help":
            if len(args) < 2:
                cli_warning("missing help option")
            else:
                command.opt_help(args[1])
        else:
            try:
                history.start_event(" ".join(self.lastcmd.split()[:2]))
                command.method(args[0])(args[1:])
            except CliException as e:
                print(e)
            except Exception:
                traceback.print_exc()
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

    def do_file(self, args):
        """Read commands from a file."""
        args = args.split()
        if len(args) < 1:
            cli_warning("missing file name.")
            return
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

    def complete_file(self, text, line, begidx, endidx):
        words = line.split()
        if len(words) < 2:
            ps = "."
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

    def do_shell(self, args):
        """Run a normal bash command."""
        os.system(args)

    def do_host(self, args):
        self.command_do(args, Host())

    def complete_host(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, Host())

    def help_host(self):
        self.command_help(Host())

    def do_history(self, args):
        self.command_do(args, History())

    def complete_history(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, History())

    def help_history(self):
        self.command_help(History())


if __name__ == '__main__':
    ClientShell().cmdloop()
