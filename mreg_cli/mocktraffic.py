import json
import os
from urllib.parse import urlparse

class MockTraffic(object):

    # Singleton
    __instance = None
    def __new__(cls):
        if MockTraffic.__instance is None:
            i = MockTraffic.__instance = object.__new__(cls)
            i.recording = False
            i.playback = False
            i.filename = None
            i.mock_data = None
            i.line_num = 0
        return MockTraffic.__instance

    # the __getattr__( ) method redirects calls to the single instance
    def __getattr__(self, name):
        print("__getattr__")
        return getattr(MockTraffic.__instance, name)

    """ Start recording http traffic, commands and console output to the given filename.
        Warning! If the file exists, it will be deleted/overwritten. """
    def start_recording(self, filename):
        i = MockTraffic.__instance
        i.recording = True
        i.filename = filename
        try:
            os.remove(filename)
        except:
            pass

    """ Prepare to read back commands, http traffic and console output from the given file. """
    def start_playback(self, filename):
        i = MockTraffic.__instance
        i.playback = True
        i.filename = filename
        i.line_num = 0
        f = open(i.filename, 'r')
        lns = f.readlines()
        f.close()
        i.mock_data = []
        for ln in lns:
            i.mock_data.append(json.loads(ln))

    def is_recording(self) -> bool:
        return MockTraffic.__instance.recording

    def is_playback(self) -> bool:
        return MockTraffic.__instance.playback

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
        f = open(MockTraffic.__instance.filename, "a+")
        f.write("%s\n" % json.dumps(x))
        f.close()

    def record_output(self,output):
        if not self.is_recording():
            return
        x = {'output':output}
        f = open(MockTraffic.__instance.filename, "a+")
        f.write("%s\n" % json.dumps(x))
        f.close()

    """ Returns only the path + query string components of a url """
    def urlpath(self, url):
        up = urlparse(url)
        if up.query != '':
            return up.path + '?' + up.query
        else:
            return up.path

    """ Pretends to perform the http call (method, url and post data),
        verifies that it was the expected http call at this point in time,
        and returns an object that can pass for a http response. """
    def get_mock_result(self, method, url, data):
        i = MockTraffic.__instance
        if not i.playback:
            raise Exception("Did not call start_playback() before get_mock_result()")
        #
        i.line_num += 1
        if i.line_num >= len(i.mock_data):
            raise Exception("Ran out of mock data, did not expect any more http calls!")
        #
        obj = i.mock_data[i.line_num-1]
        method = method.upper()
        url = self.urlpath(url)
        if method != obj['method'] or url != obj['url'] or data != obj['data']:
            raise Exception("%s(%d):\nExpected: %s %s %s\nDid:      %s %s %s" %
                (i.filename, i.line_num, obj['method'],obj['url'],obj['data'],method,url,data))
        #
        class MockResponse:
            def __init__(self, json_data, status_code, ok, reason):
                self.json_data = json_data
                self.status_code = status_code
                self.ok = ok
                self.reason = reason
            def json(self):
                return self.json_data
        return MockResponse(obj.get('json_data',None), obj.get('status',0), obj.get('ok',False), obj.get('reason',''))

    """ Records an http call (method, url and postdata) and the response. """
    def record(self, method, url, data, result):
        if not self.is_recording():
            return
        x = {
            'method': method.upper(),
            'url': self.urlpath(url),
            'data': data,
            'ok': result.ok,
            'status': result.status_code,
            'reason': result.reason,
        }
        try:
            x['json_data'] = result.json()
        except:
            if len(result.content)>0:
                x['body'] = result.content.decode('utf-8')
        f = open(MockTraffic.__instance.filename, "a+")
        f.write("%s\n" % json.dumps(x))
        f.close()

    """ Returns the next command from the playback data. """
    def get_next_command(self):
        i = MockTraffic.__instance
        if not i.playback:
            raise Exception("Did not call start_playback() before get_next_command()")
        i.line_num += 1
        if i.line_num >= len(i.mock_data):
            return None
        obj = i.mock_data[i.line_num-1]
        if 'command' not in obj:
            if 'method' in obj:
                raise Exception("%s(%d): Expected a http call" % (i.filename,i.line_num))
            elif 'output' in obj:
                raise Exception("%s(%d): Expected some output" % (i.filename,i.line_num))
        return obj['command']

    """ Compares actual console output to what was the expected output at this point """
    def compare_with_expected_output(self,actual_output):
        i = MockTraffic.__instance
        if not i.playback:
            raise Exception("Did not call start_playback() before expect_output()")
        i.line_num += 1
        if i.line_num >= len(i.mock_data):
            raise Exception("Didn't expect any more output after end of script:\n\"%s\"" % actual_output)
        if not 'output' in i.mock_data[i.line_num-1]:
            raise Exception("%s: Didn't expect any output on line %d:\n\"%s\"" % (i.filename, i.line_num, actual_output))
        expected = i.mock_data[i.line_num-1]['output']
        if actual_output != expected:
            raise Exception("%s(%d): The actual output differs from the expected output.\nGot:      \"%s\"\nExpected: \"%s\"" 
                % (i.filename, i.line_num, actual_output, expected))
