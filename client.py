import cmd
import traceback

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
        if args[0] == "help":
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
