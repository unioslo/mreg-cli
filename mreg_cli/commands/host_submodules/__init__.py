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

# We have to import each of the submodules explictly here in order to
# ensure they are included when we build binaries with PyInstaller.
# We also cannot do `from . import *`. Each module must be specified.
from __future__ import annotations

from . import a_aaaa, bacnet, cname, core, rr

__all__ = [
    "a_aaaa",
    "bacnet",
    "cname",
    "core",
    "rr",
]
