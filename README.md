# MREG CLI 
Command Line Interface for Mreg

##### client.py
Implementation of the client shell, using the python standard library module `cmd`.
When creating a new command the only change needed here is to add the methods:
```python
    def do_<command-name>(self, args):
        self.command_do(args, <command-object>)

    def complete_<command-name>(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, <command-object>)

    def help_<command-name>(self):
        self.command_help(<command-object>)
```

##### commands.py
Implementation of the commands. `CommandBase` is the base class which uses inspection 
to generate documentation and execute commands.  
When creating a new command create a class which inherits `CommandBase` and add 
methods starting with `opt_` to add options to the command:
```python
class <command-class>(CommandBase):
    """
    Doc string for the command. Displayed as help string when typing "help <command>"
    """

    def opt_<command-option>(self, args):
        """
        Doc string for command option. Displayed as help string when typing "<command> help <option>"
        """
        pass
```

##### util.py
Contains most of the helper functions for the project.

##### history.py
Implementation of (basic) history recording. History recordings must be explicitly called
from the code of command implementations. History is not saved to file.

##### config.py
Contains `cli_config(config_file, required_fields)`  which reads a simple key=value config
file and returns a dict. Raises an exception if any of the required_fields are missing.

##### log.py
Contains functions for handling logging. The log entries are on the format: 
```
2018-01-01 15:01:02 username [ERROR] host add: message
```

The log functions are:

`cli_info(msg, print_msg=False)` - log a [OK] message. Doesn't print to stdout by default.
`cli_warning(msg, print_msg=True)` - log a [WARNING] message. Print to stdout by default.
`cli_error(msg, print_msg=True)` - log a [ERROR] message. Print to stdout by default.
