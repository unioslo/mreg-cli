#!/usr/bin/env python3.12
# -*- coding: utf-8 -*-
"""Run script for pyinstaller.

Create a standalone executable as:

pyinstaller --name mreg-cli run.py -F --hidden-import=mreg_cli.commands.host_submodules

The finished binary will be in the `dist` directory.

The hidden import is required to include the host submodules in the executable,
due to using dynamic imports.
"""
from __future__ import annotations

import re
import sys

from mreg_cli.main import main

if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\.pyw|\.exe)?$", "", sys.argv[0])
    sys.exit(main())
