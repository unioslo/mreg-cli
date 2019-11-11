import json

from dateutil.parser import parse

from .log import cli_warning
from .util import get_list


def get_history_items(name, resource, data_relation=None):
    # First check if any model id with the name exists
    base_path = f"/api/v1/history/?resource={resource}"
    ret = get_list(f"{base_path}&name={name}")
    if len(ret) == 0:
        cli_warning(f"No history found for {name}")
    # Get all model ids, a group gets a new one when deleted and created again
    model_ids = { str(i["model_id"]) for i in ret }
    model_ids = ",".join(model_ids)
    ret = get_list(f"{base_path}&model_id__in={model_ids}")
    if data_relation is not None:
        ret.extend(get_list(f"/api/v1/history/?data__relation={data_relation}&data__id__in={model_ids}"))
    return ret


def print_history_items(ownname, items):

    def _remove_unneded_keys(data):
        for key in ('id', 'created_at', 'updated_at',):
            data.pop(key, None)

    for i in sorted(items, key=lambda i: parse(i['timestamp'])):
        timestamp = parse(i['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        msg = ''
        if isinstance(i['data'], dict):
            data = i['data']
        else:
            data = json.loads(i['data'])
        action = i['action']
        model = i['model']
        if action in ('add', 'remove'):
            if i['name'] == ownname:
                msg = data['name']
            else:
                msg = i['resource'] + ' ' + i['name']
                if action == 'add':
                    action = 'add to'
                elif action == 'remove':
                    action = 'remove from'
        elif action == 'create':
            msg = ', '.join(f"{k} = '{v}'" for k,v in data.items())
        elif action == 'update':
            if model in ('Ipaddress', ):
                msg = data['current_data']['ipaddress'] + ', '
            changes = []
            for key, newval in data['update'].items():
                oldval = data["current_data"][key] or 'not set'
                newval = newval or 'not set'
                changes.append(f"{key}: {oldval} -> {newval}")
            msg += ','.join(changes)
        elif action == 'destroy':
            _remove_unneded_keys(data)
            if model == 'Host':
                msg = "deleted " + i["name"]
            else:
                msg = ', '.join(f"{k} = '{v}'" for k,v in data.items())
        else:
            cli_warning(f'Unhandled history entry: {i}')

        print(f"{timestamp} [{i['user']}]: {model} {action}: {msg}")
