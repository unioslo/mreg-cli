config_file = "cli.config"


def cli_config(required_fields=[]):
    conf = {}
    with open(config_file) as f:
        line = f.readline()
        while line:
            if not line.strip():
                line = f.readline()
                continue
            line = line.rsplit("#", 1)[0]
            pair = line.split("=")
            conf[pair[0].strip()] = pair[1].strip()
            line = f.readline()

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
