import atexit
import json
import os
from typing import Any, Dict
from urllib.parse import urlencode, urlparse

import requests


def remove_dict_key_recursive(obj, key: str) -> None:
    if isinstance(obj, list):
        for elem in obj:
            remove_dict_key_recursive(elem, key)
        return
    elif isinstance(obj, dict):
        try:
            del obj[key]
        except KeyError:
            pass
        for other_value in obj.values():
            remove_dict_key_recursive(other_value, key)


class Recorder:

    # Singleton
    __instance = None

    def __new__(cls):
        if Recorder.__instance is None:
            i = Recorder.__instance = object.__new__(cls)
            i.recording = False
            i.filename = None
            i.recorded_data = []
        return Recorder.__instance

    # the __getattr__( ) method redirects calls to the single instance
    def __getattr__(self, name):
        if self != Recorder.__instance:
            return getattr(Recorder.__instance, name)
        else:
            raise AttributeError(
                "%r object has no attribute %r" % (self.__class__.__name__, name)
            )

    def save_recording(self) -> None:
        i = Recorder.__instance
        f = open(i.filename, "w")
        f.write(json.dumps(i.recorded_data, indent=2))
        f.close()

    """ Start recording http traffic, commands and console output to the given filename.
        Warning! If the file exists, it will be deleted/overwritten. """

    def start_recording(self, filename: str) -> None:
        i = Recorder.__instance
        i.recording = True
        i.filename = filename
        atexit.register(Recorder.save_recording, self)
        try:
            os.remove(filename)
        except:
            pass

    def is_recording(self) -> bool:
        return Recorder.__instance.recording

    def record_command(self, cmd: str) -> None:
        if not self.is_recording():
            return
        # trim spaces, remove comments
        cmd = cmd.lstrip()
        if cmd.find("#") > -1:
            cmd = cmd[0 : cmd.find("#")].rstrip()
        # don't log empty commands
        if (
            cmd == ""
        ):  # Compare to empty string to avoid being tripped up by strings having false-like values (0, False, etc)
            return
        x = {"command": cmd}
        Recorder.__instance.recorded_data.append(x)

    def record_output(self, output: str) -> None:
        if not self.is_recording():
            return
        x = {"output": output}
        Recorder.__instance.recorded_data.append(x)

    """ Returns only the path + query string components of a url """

    def urlpath(self, url: str, params: str) -> str:
        if params:
            url = f"{url}?{urlencode(params)}"
        up = urlparse(url)
        if (
            up.query != ""
        ):  # Compare to empty string to avoid being tripped up by strings having false-like values (0, False, etc)
            return up.path + "?" + up.query
        else:
            return up.path

    """ Records an http call (method, url and postdata) and the response. """

    def record(
        self,
        method: str,
        url: str,
        params: str,
        data: Dict[str, Any],
        result: requests.Response,
    ) -> None:
        if not self.is_recording():
            return
        x = {
            "method": method.upper(),
            "url": self.urlpath(url, params),
            "data": data,
            "status": result.status_code,
        }
        try:
            obj = result.json()
            keys_to_remove = [
                "id",
                "created_at",
                "updated_at",
                "serialno",
                "serialno_updated_at",
                "create_date",
            ]
            for key in keys_to_remove:
                remove_dict_key_recursive(obj, key)
            x["response"] = obj
        except requests.JSONDecodeError:
            s = result.content.decode("utf-8").strip()
            if (
                s != ""
            ):  # Compare to empty string to avoid being tripped up by strings having false-like values (0, False, etc)
                x["response"] = s
        Recorder.__instance.recorded_data.append(x)
