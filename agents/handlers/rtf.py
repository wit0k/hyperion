""" Requirements:
- sudo -H pip install -U https://github.com/decalage2/oletools/archive/master.zip
- pip install yara-python --upgrade
"""
import os.path
import re
import logging

from oletools import rtfobj, oleobj

import yara

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

    RE_PATTERNS = (
        ('URL', re.compile(URL_RE)),
        ('IPv4 address', re.compile(IPv4)),
        ('E-mail address', re.compile(r'(?i)\b[A-Z0-9._%+-]+@' + SERVER + '\b')),
        ('Domain name', re.compile(r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)')),
        ("Executable file name", re.compile(
            r"(?i)\b\w+\.(EXE|PIF|GADGET|MSI|MSP|MSC|VBS|VBE|VB|JSE|JS|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR|HTA|CPL|CLASS|JAR|PS1XML|PS1|PS2XML|PS2|PSC1|PSC2|SCF|LNK|INF|REG)\b"))
    )

    def __init__(self, file):
        """ Init the class object """
        self.file = file

    """ Main module functions """
    def run(self, task, param=None):

        meta_data = {}
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
                file_buffer_stripped = self._strip_keycodes(file_buffer.decode("utf8"))
                meta_data["file_sig"] = scan.scan_buffer(file_buffer_stripped)

        """ ... """

        handler = self._get_handler(meta_data["file_sig"])
        if handler:
            handler(file_buffer_stripped, meta_data)

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
            print(output[0]["file_name"], output[0]["obj_offset"], output[0]["file_sig"], output[0]["ole_yara_sig"], output[0]["ole_regex_strings"])

        else:
            logger.warning(f"Unsupported file: {self.file}")

        """ Properly close the task before returning from the function"""
        self.end(task)

    def end(self, task_obj):
        task_obj.task_done()

    """ CVE specific handlers """
    def _CVE_2018_0802(self, rtf_stripped, meta_data):
        return None

    mappings_yara_to_handler = {
        'rtf_CVE_2018_0802_v1': _CVE_2018_0802
    }

    def _get_handler(self, yara_sig_name):
        """ For unknown reason not working yet, even if yara_sig_name match the dict key... ? """
        try:
            return self.mappings_yara_to_handler[yara_sig_name]
        except KeyError:
            return None

    """ Helper functions """
    def _strip_keycodes(self, rtf_data):
        rtf_stripped = (re.sub(r"(?:\{\\\*\\keycode[0-9]+ {1})([0-9a-fA-F]+)\}", r"\1", rtf_data))
        return rtf_stripped

    def _regex_scan(self, strings):
        """
        Taken from olevba:

        Detect if the VBA code contains specific patterns such as IP addresses,
        URLs, e-mail addresses, executable file names, etc.

        :param vba_code: str, VBA source code
        :return: list of str tuples (pattern type, value)
        """
        results = []
        #found = set()
        for pattern_type, pattern_re in self.RE_PATTERNS:
            for match in pattern_re.finditer(strings):
                value = match.group()
                #if value not in found:
                results.append(value)
                    #found.add(value)
        return results





