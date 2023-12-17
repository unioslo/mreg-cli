"""Submodules for the host command.

The host command has a lot of subcommands, so they are broken up into
submodules. Each of these modules registers their commands with the
:py:class:`mreg_cli.commands.host.HostCommands` class, which is the main
command class for the host command.

This is done by importing the command registry directly from the host
command module, which is a bit hacky, but it works.

Note: This design will imply circular imports, so the core host command
imports the submodules after it has been initialized.
"""
