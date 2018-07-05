from typing import *
import re


def cli_config(config_file: str = "cli.conf", required_fields: Sequence[str] = []) -> dict:
    conf = dict()
    with open(config_file) as f:
        num = 0
        line = f.readline().strip()
        while line:
            num = num + 1
            if not line:
                line = f.readline().strip()
                continue
            if not re.match("^\s*(\w[\w\d-]*\s*=\s*.+)?\s*(#.*)?$", line):
                raise Exception(
                    "Invalid config file: cannot understand line {}: {}".format(num, line))
            line = line.rsplit("#", 1)[0]
            pair = line.split("=")
            conf[pair[0].strip()] = pair[1].strip()
            line = f.readline().strip()

    missing_field = False
    for field in required_fields:
        try:
            conf[field]
        except KeyError:
            print("Missing field in config file: {}".format(field))
            missing_field = True
    if missing_field:
        raise Exception("Invalid config file: missing required field(s).")
    return conf
