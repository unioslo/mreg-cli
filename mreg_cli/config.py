from typing import *
import re


# TODO: Rewrite with/use "configparser" from std library instead
def cli_config(config_file: str = "cli.conf", required_fields: Sequence[str] = []) -> dict:
    conf = dict()
    with open(config_file) as f:
        num = 0
        while True:
            line = f.readline()
            if not line:
                break
            num += 1
            m = re.match("^\s*(?P<key>\w[\w\d-]*)\s*=\s*(?P<value>.+)\s*(#.*)?$", line)
            if m:
                conf[m.group("key")] = m.group("value")

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
