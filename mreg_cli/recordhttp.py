import json
import os
from urllib.parse import urlparse, urlencode
import atexit
from requests import JSONDecodeError

def remove_dict_key_recursive(obj, key:str):
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

class RecordHttp(object):

    # Singleton
    __instance = None
    def __new__(cls):
        if RecordHttp.__instance is None:
            i = RecordHttp.__instance = object.__new__(cls)
            i.recording = False
            i.filename = None
            i.recorded_data = []
        return RecordHttp.__instance

    # the __getattr__( ) method redirects calls to the single instance
    def __getattr__(self, name):
        if self != RecordHttp.__instance:
            return getattr(RecordHttp.__instance, name)
        else:
            raise AttributeError("%r object has no attribute %r" % (self.__class__.__name__, name))

    def save_recording(self):
        i = RecordHttp.__instance
        f = open(i.filename, "w")
        f.write(json.dumps(i.recorded_data, indent=2))
        f.close()

    """ Start recording http traffic, commands and console output to the given filename.
        Warning! If the file exists, it will be deleted/overwritten. """
    def start_recording(self, filename):
        i = RecordHttp.__instance
        i.recording = True
        i.filename = filename
        atexit.register(RecordHttp.save_recording, self)
        try:
            os.remove(filename)
        except:
            pass

    def is_recording(self) -> bool:
        return RecordHttp.__instance.recording

    def record_command(self,cmd):
        if not self.is_recording():
            return
        # trim spaces, remove comments
        cmd = cmd.lstrip()
        if cmd.find("#")>-1:
            cmd = cmd[0:cmd.find("#")].rstrip()
        # don't log empty commands
        if cmd == '':
            return
        x = {'command':cmd}
        RecordHttp.__instance.recorded_data.append(x)

    def record_output(self,output):
        if not self.is_recording():
            return
        x = {'output':output}
        RecordHttp.__instance.recorded_data.append(x)

    """ Returns only the path + query string components of a url """
    def urlpath(self, url, params):
        if params:
            url = f"{url}?{urlencode(params)}"
        up = urlparse(url)
        if up.query != '':
            return up.path + '?' + up.query
        else:
            return up.path

    """ Records an http call (method, url and postdata) and the response. """
    def record(self, method, url, params, data, result):
        if not self.is_recording():
            return
        x = {
            'method': method.upper(),
            'url': self.urlpath(url, params),
            'data': data,
            'status': result.status_code
        }
        try:
            obj = result.json()
            keys_to_remove = ['id','created_at','updated_at','serialno','serialno_updated_at','create_date']
            for key in keys_to_remove:
                remove_dict_key_recursive(obj, key)
            x['response'] = obj
        except JSONDecodeError:
            s = result.content.decode('utf-8').strip()
            if s != "":
                x['response'] = s
        RecordHttp.__instance.recorded_data.append(x)
