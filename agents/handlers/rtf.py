""" Requirements:
- sudo -H pip install -U https://github.com/decalage2/oletools/archive/master.zip
- pip install yara-python --upgrade
"""
import os.path
import re
import logging
import collections

from oletools import rtfobj, oleobj
logger = logging.getLogger('hyperion')

class rtf():


    name = "rtf"
    obj_sig_len = 4
    output_format = ["file_name", "file_sig", "obj_count", "obj_offset", "ole_type", "ole_size", "obj_sig", "ole_yara_sig",
                     "ole_regex_strings",
                     "ole_strings"]

    SCHEME = r'\b(?:http|ftp)s?'
    TLD = r'(?:xn--[a-zA-Z0-9]{4,20}|[a-zA-Z]{2,20})'
    DNS_NAME = r'(?:[a-zA-Z0-9\-\.]+\.' + TLD + ')'
    NUMBER_0_255 = r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])'
    IPv4 = r'(?:' + NUMBER_0_255 + r'\.){3}' + NUMBER_0_255
    SERVER = r'(?:' + IPv4 + '|' + DNS_NAME + ')'
    PORT = r'(?:\:[0-9]{1,5})?'
    SERVER_PORT = SERVER + PORT
    URL_PATH = r'(?:/[a-zA-Z0-9\-\._\?\,\'/\\\+&%\$#\=~]*)?'  # [^\.\,\)\(\s"]
    URL_RE = SCHEME + r'\://' + SERVER_PORT + URL_PATH
    re_url = re.compile(URL_RE)

    RE_PATTERNS = {
        'url_v1': re.compile(URL_RE),
        'url_v2': re.compile(r'[a-zA-Z]+://[-a-zA-Z0-9.]+(?:/[-a-zA-Z0-9+&@#/%=~_|!:,.;]*)?(?:\?[a-zA-Z0-9+&@#/%=~_|!:,.;]*)?'),
        'ipv4_v1': re.compile(IPv4),
        'ipv4_v2': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'),
        'email_v1': re.compile(r'(?i)\b[A-Z0-9._%+-]+@' + SERVER + '\b'),
        'email_v2': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}'),
        'domain': re.compile(r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)'),
        "exe_name": re.compile(r"(?i)\b\w+\.(EXE|PIF|GADGET|MSI|MSP|MSC|VBS|VBE|VB|JSE|JS|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR|HTA|CPL|CLASS|JAR|PS1XML|PS1|PS2XML|PS2|PSC1|PSC2|SCF|LNK|INF|REG)\b"),
        'btc': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
        'file_path_win': re.compile(r'((?:(?:[A-Za-z]:)|//home)[^\.]+\.[A-Za-z]{2,8})')
    }

    def __init__(self, file):
        """ Init the class object """
        self.file = file

    """ Main module functions """
    def run(self, task, param=None):

        meta_data = collections.OrderedDict()
        output = []
        file_buffer = ""
        file_buffer_stripped = ""

        """ Retrieve necessary objects """
        scan = task.properties["scanner"]

        """ Scan the file content """
        meta_data["file_sig"] = ""
        with open(self.file, 'rb') as file_content:
            file_buffer = file_content.read()
            meta_data["file_sig"] = scan.scan_buffer(file_buffer)

            # Scan stripped file content if previous match was not found
            if not meta_data["file_sig"]:
                try:
                    file_buffer_stripped = self._strip_keycodes(file_buffer.decode("utf8"))
                    meta_data["file_sig"] = scan.scan_buffer(file_buffer_stripped)
                except UnicodeDecodeError:
                    logger.warning(f"UnicodeDecodeError: Failed to decode -> {self.file}")

        """ Get the right handler by file_sig """
        handler = self._get_handler(meta_data["file_sig"])
        if handler:
            if file_buffer_stripped:
                handler(self, file_buffer_stripped, meta_data)
            else:
                handler(self, file_buffer, meta_data)

        """ Get info about all objects available """
        _objects = list(rtfobj.rtf_iter_objects(self.file))

        if _objects:
            for offset, orig_len, data in _objects:
                meta_data["file_name"] = os.path.basename(self.file)
                meta_data["obj_count"] = len(_objects)
                meta_data["obj_size"] = len(data)
                meta_data["obj_offset"] = '0x%08X' % offset
                meta_data["obj_sig"] = str(data[:self.obj_sig_len])
                try:
                    _oleobj = oleobj.OleObject()
                    _oleobj.parse(data)
                    meta_data["ole_type"] = _oleobj.class_name
                    meta_data["ole_size"] = _oleobj.data_size
                except Exception:
                    meta_data["ole_type"] = ""
                    meta_data["ole_size"] = ""

                try:
                    unique_strings = ""
                    data_str = data.decode(errors='ignore')
                    unique_strings = "\r".join(list(set(re.findall("[^\x00-\x1F\x7F-\xFF]{3,}", data_str))))
                except Exception:
                    unique_strings = ""

                meta_data["ole_strings"] = unique_strings

                """ Scan the data object content """
                ole_yarasig = ""
                #for sig in scan.scan_buffer(data):
                ole_yarasig = scan.scan_buffer(data)
                meta_data["ole_yara_sig"] = ole_yarasig

                matched_strings = ""
                matched_strings = self._regex_scan(unique_strings)
                meta_data["ole_regex_strings"] = matched_strings

                output.append(meta_data.copy())
                meta_data.clear()

                # Need to find out how to share the result with the caller...
                #print(output[0]["file_name"], output[0]["obj_offset"], output[0]["file_sig"], output[0]["ole_yara_sig"], output[0]["ole_regex_strings"])

        else:
            logger.warning(f"Unsupported file: {self.file}")

        """ Properly close the task before returning from the function"""
        self.end(task, output)

    def end(self, task_obj, output):
        task_obj.task_done(output)

    """ CVE specific handlers """
    def _CVE_2018_0802(self, rtf_stripped, meta_data):
        return None

    """ mapping has to be an exact yara_rule.name """
    mappings_yara_to_handler = {
        'rtf_CVE_2018_0802_v1': _CVE_2018_0802,
        'test': "est"
    }

    def _get_handler(self, yara_sig_name):
        """ For unknown reason not working yet, even if yara_sig_name match the dict key... ? """
        try:
            if yara_sig_name:
                return self.mappings_yara_to_handler[yara_sig_name.strip()]
            else:
                return None
        except KeyError:
            return None

    """ Helper functions """
    def _strip_keycodes(self, rtf_data):
        rtf_stripped = (re.sub(r"(?:\{\\\*\\keycode[0-9]+ {1})([0-9a-fA-F]+)\}", r"\1", rtf_data))
        return rtf_stripped

    def _regex_scan(self, strings):

        """ Taken from olevba: """

        results = []
        found = set()
        for pattern_type, pattern_re in self.RE_PATTERNS.items():
            for match in pattern_re.finditer(strings):
                value = match.group()
                if value not in found:
                    results.append(value)
                    found.add(value)
        return results





