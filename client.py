import os
import cmd
import traceback
from pathlib import Path

from util import *
from commands import *


class ClientShell(cmd.Cmd):
    intro = "Welcome to mreg cli. Type help or ? for help."
    prompt = "mreg> "

    #####################################################################
    #   Functions which automatically handles any CommandBase() child   #
    #####################################################################

    def command_do(self, args, command):
        assert isinstance(command, CommandBase)
        args = args.split()
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
                command.do(args[0])(args[1:])
            except UnknownOptionError as e:
                cli_error(e)
            except Exception:
                traceback.print_exc()

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


if __name__ == '__main__':
    ClientShell().cmdloop()
