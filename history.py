import requests
import json

from log import *


class HistoryEvent:
    def __init__(self, name: str = "", index: int = -1):
        self.requests = []
        self.name = name
        self.index = index
        self.redoable = True
        self.undoable = True

    def __str__(self):
        s = "{:<3} {}:".format(self.index, self.name)
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
        for request in reversed(self.requests):
            if request["name"] == "POST":
                res = requests.delete(url=request["url"])
            elif request["name"] == "PATCH":
                res = requests.patch(url=request["url"], data=request["old_data"])
            elif request["name"] == "DELETE":
                res = requests.post(url=request["url"], data=requests["old_data"])
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

    def redo(self):
        """Redo this event"""
        for request in self.requests:
            if request["name"] == "POST":
                res = requests.post(url=request["url"], data=request["new_data"])
            elif request["name"] == "PATCH":
                res = requests.patch(url=request["url"], data=request["new_data"])
            elif request["name"] == "DELETE":
                res = requests.delete(url=request["url"])
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

    def record_post(self, url: str, response: requests.Response, new_data: dict = None) -> None:
        """Record a POST request in the current event"""
        self.current.add_post(url, response, new_data)
        self.current.add_request(
            name="POST",
            url=url,

        )

    def record_patch(self, url: str, response: requests.Response, old_data: dict = None,
                     new_data: dict = None) -> None:
        """Record a PATCH request in the current event"""
        self.current.add_patch(url, response, old_data=old_data, new_data=new_data)

    def record_delete(self, url: str, response: requests.Response, old_data: dict = None) -> None:
        """Record a DELETE request in the current event"""
        self.current.add_delete(url, response, old_data)

    def record_get(self, url: str, response: requests.Response) -> None:
        """Record a GET request in the current event"""
        self.current.add_get(url, response)

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
