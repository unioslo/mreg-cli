import json

from dateutil.parser import parse

from .log import cli_warning
from .util import get_list


def get_history_items(name, resource, data_relation=None):
    # First check if any model id with the name exists
    path = "/api/v1/history/"
    params = {
        "resource": resource,
        "name": name,
    }
    ret = get_list(path, params=params)
    if len(ret) == 0:
        cli_warning(f"No history found for {name}")
    # Get all model ids, a group gets a new one when deleted and created again
    model_ids = {str(i["model_id"]) for i in ret}
    model_ids = ",".join(model_ids)
    params = {
        "resource": resource,
        "model_id__in": model_ids,
    }
    ret = get_list(path, params=params)
    if data_relation is not None:
        params = {
            "data__relation": data_relation,
            "data__id__in": model_ids,
        }
        ret.extend(get_list(path, params=params))
    return ret


def print_history_items(ownname, items):
    def _remove_unneded_keys(data):
        for key in (
            "id",
            "created_at",
            "updated_at",
        ):
            data.pop(key, None)

    output = ""

    for i in sorted(items, key=lambda i: parse(i["timestamp"])):
        timestamp = parse(i["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        msg = ""
        if isinstance(i["data"], dict):
            data = i["data"]
        else:
            data = json.loads(i["data"])
        action = i["action"]
        model = i["model"]
        if action in ("add", "remove"):
            if i["name"] == ownname:
                msg = data["name"]
            else:
                msg = i["resource"] + " " + i["name"]
                if action == "add":
                    action = "add to"
                elif action == "remove":
                    action = "remove from"
        elif action == "create":
            msg = ", ".join(f"{k} = '{v}'" for k, v in data.items())
        elif action == "update":
            if model in ("Ipaddress",):
                msg = data["current_data"]["ipaddress"] + ", "
            changes = []
            for key, newval in data["update"].items():
                oldval = data["current_data"][key] or "not set"
                newval = newval or "not set"
                changes.append(f"{key}: {oldval} -> {newval}")
            msg += ",".join(changes)
        elif action == "destroy":
            _remove_unneded_keys(data)
            if model == "Host":
                msg = "deleted " + i["name"]
            else:
                msg = ", ".join(f"{k} = '{v}'" for k, v in data.items())
        else:
            cli_warning(f"Unhandled history entry: {i}")

        output += f"{timestamp} [{i['user']}]: {model} {action}: {msg}\n"

    return output
