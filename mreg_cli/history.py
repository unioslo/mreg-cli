import json

import requests

from .cli import Flag, cli
from .log import cli_error, cli_info, cli_warning

# NOTE HISTORY: General notes and shortcomings of history tracking:
# Not generic.
#   History must be explicitly recorded in the code where it's needed.
# Not flexible.
#   Undo/redo actions need to receive all necessary information when recording an event and there's
#   no logic for making smart undo/redo actions.
# No foreign key understanding.
#   The history got no concept of foreign key/table relations in the database, so all changes in
#   which a foreign key is involved (directly or indirectly) is problematic.
# Undo/redo is not RESTfull...

# QUESTION HISTORY: kanskje redo/undo kan løses ved å generere CLI kommandoer som utfører redo/undo operasjonene?


class HistoryEvent:
    def __init__(self, name: str = "", index: int = -1):
        self.requests = []
        self.name = name
        self.index = index
        self.redoable = True
        self.undoable = True

    def __str__(self):
        s = "{:<3} {} ({} redo, {} undo):".format(
            self.index,
            self.name,
            "can" if self.redoable else "cannot",
            "can" if self.undoable else "cannot",
        )
        for request in self.requests:
            s += "\n\t{} {}".format(
                request["name"],
                request["url"],
            )
        return s

    def __repr__(self):
        return "<{} event with {} requests>".format(self.name, len(self.requests))

    def add_request(self, name: str, url: str, resource_name: str, old_data: dict, new_data: dict,
                    redoable: bool, undoable: bool) -> None:
        """Add a recording of a request which happened during this event."""
        self.requests.append({
            "name": name,
            "url": url,
            "resource_name": resource_name,
            "old_data": old_data,
            "new_data": new_data,
        })
        if not redoable:
            self.redoable = False
        if not undoable:
            self.undoable = False

    def undo(self):
        """Undo this event"""
        if not self.undoable:
            return
        for request in reversed(self.requests):
            if request["name"] == "POST":
                url = "{}{}".format(request["url"], request["resource_name"])
                res = requests.delete(url)
                msg = "deleted {}".format(url)
            elif request["name"] == "PATCH":
                res = requests.patch(url=request["url"], data=request["old_data"])
                msg = "patched {}".format(request["url"])
            elif request["name"] == "DELETE":
                url = request["url"].rsplit(sep='/', maxsplit=1)[0] + "/"
                res = requests.post(url, data=request["old_data"])
                msg = "posted {}".format(url)
            else:
                continue
            if not res.ok:
                # QUESTION HISTORY: hvordan egentlig håndtere feil under undo av event?
                message = "{} \"{}\": {}: {}".format(
                    request["name"],
                    request["url"],
                    res.status_code,
                    res.reason
                )
                try:
                    body = res.json()
                except ValueError:
                    pass
                else:
                    message += "\n{}".format(json.dumps(body, indent=2))
                cli_error(message)
            else:
                cli_info("{}".format(msg), print_msg=True)

    def redo(self):
        """Redo this event"""
        if not self.redoable:
            return
        for request in self.requests:
            if request["name"] == "POST":
                res = requests.post(url=request["url"], data=request["new_data"])
                msg = "posted {}".format(request["url"])
            elif request["name"] == "PATCH":
                res = requests.patch(url=request["url"], data=request["new_data"])
                msg = "patched {}".format(request["url"])
            elif request["name"] == "DELETE":
                res = requests.delete(url=request["url"])
                msg = "deleted {}".format(request["url"])
            else:
                continue
            if not res.ok:
                # QUESTION HISTORY: hvordan egentlig håndtere feil under redo av event?
                message = "{} \"{}\": {}: {}".format(
                    request["name"],
                    request["url"],
                    res.status_code,
                    res.reason
                )
                try:
                    body = res.json()
                except ValueError:
                    pass
                else:
                    message += "\n{}".format(json.dumps(body, indent=2))
                cli_error(message)
            else:
                cli_info("{}".format(msg), print_msg=True)


class History:
    def __init__(self):
        self.events = []
        self.count = 0
        self.current = HistoryEvent()
        self.in_event = False

    def start_event(self, name: str) -> None:
        """Start a new event which will record requests until it is ended"""
        if not self.in_event:
            self.in_event = True
            self.current = HistoryEvent(name, index=self.count)

    def end_event(self) -> None:
        """End the current event"""
        if self.in_event:
            self.in_event = False
            if len(self.current.requests) > 0:
                self.events.append(self.current)
                self.count += 1
            # Setting current to a dummy event which will be lost when a new event is started.
            self.current = HistoryEvent()

    def record_post(self, url: str, resource_name: str, new_data: dict, redoable: bool = True,
                    undoable: bool = True) -> None:
        """Record a POST request in the current event"""
        self.current.add_request(
            name="POST",
            url=url,
            resource_name=resource_name,
            old_data=dict(),
            new_data=new_data,
            redoable=redoable,
            undoable=undoable,
        )

    def record_patch(self, url: str, new_data: dict, old_data: dict,
                     redoable: bool = True, undoable: bool = True) -> None:
        """Record a PATCH request in the current event"""
        self.current.add_request(
            name="PATCH",
            url=url,
            resource_name="",
            old_data=old_data,
            new_data=new_data,
            redoable=redoable,
            undoable=undoable,
        )

    def record_delete(self, url: str, old_data: dict, redoable: bool = True,
                      undoable: bool = True) -> None:
        """Record a DELETE request in the current event"""
        self.current.add_request(
            name="DELETE",
            url=url,
            resource_name="",
            old_data=old_data,
            new_data=dict(),
            redoable=redoable,
            undoable=undoable,
        )

    def record_get(self, url: str, redoable: bool = True, undoable: bool = True) -> None:
        """Record a GET request in the current event"""
        self.current.add_request(
            name="GET",
            url=url,
            resource_name="",
            old_data=dict(),
            new_data=dict(),
            redoable=redoable,
            undoable=undoable,
        )

    def print(self):
        for e in self.events:
            print(e)

    def redo(self, event_num: int):
        """Redo the given command (event) or the given request of the given command."""
        if not 0 <= event_num < len(self.events):
            cli_warning("invalid history command number: {}".format(event_num))
        else:
            e = self.events[event_num]
            if not e.redoable:
                cli_warning("cannot redo {}".format(e.name))
            else:
                e.redo()

    def undo(self, event_num: int):
        """Redo the given command (event) or the given request of the given command."""
        if not 0 <= event_num < len(self.events):
            cli_warning("invalid history command number: {}".format(event_num))
        else:
            e = self.events[event_num]
            if not e.undoable:
                cli_warning("cannot undo {}".format(e.name))
            else:
                e.undo()


history = History()

###############################################################################
#                                                                             #
#   History CLI command                                                       #
#                                                                             #
###############################################################################

####################################
#  Add the main command 'history'  #
####################################

history_ = cli.add_command(
    prog='history',
    description='Undo, redo or print history for this program session.',
)


#########################################
# Implementation of sub command 'print' #
#########################################

def print_(args):
    print('pringing history.')


history_.add_command(
    prog='print',
    description='Print the history',
    short_desc='Print the history',
    callback=print_,
)


########################################
# Implementation of sub command 'redo' #
########################################

def redo(args):
    print('redo:', args.num)


history_.add_command(
    prog='redo',
    description='Redo some history event given by NUM (GET '
                'requests are not redone)',
    short_desc='Redo history.',
    callback=redo,
    flags=[
        Flag('num',
             description='History number of the event to redo.',
             metavar='NUM'),
    ]
)


########################################
# Implementation of sub command 'undo' #
########################################

def undo(args):
    print('undo:', args.num)


history_.add_command(
    prog='undo',
    description='Undo some history event given by <history-number> (GET '
                'requests are not redone)',
    short_desc='Undo history.',
    callback=undo,
    flags=[
        Flag('num',
             description='History number of the event to undo.',
             metavar='NUM'),
    ]
)
