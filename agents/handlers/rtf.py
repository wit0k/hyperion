""" Requirements:
- sudo -H pip install -U https://github.com/decalage2/oletools/archive/master.zip
- pip install yara-python --upgrade
"""
import os.path
import re
import logging
import time

import hashlib

from oletools import rtfobj, oleobj
from ..core.yarascan import *

logger = logging.getLogger('hyperion')

class rtf():

    name = "rtf"
    obj_sig_len = 4
    output_format = ["filename", "obj_count", "obj_offset", "ole_type", "ole_size", "obj_sig", "ole_yara_sig", "ole_regex_strings",
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
        ("Executable file name", re.compile(r"(?i)\b\w+\.(EXE|PIF|GADGET|MSI|MSP|MSC|VBS|VBE|VB|JSE|JS|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR|HTA|CPL|CLASS|JAR|PS1XML|PS1|PS2XML|PS2|PSC1|PSC2|SCF|LNK|INF|REG)\b"))
    )

    def __init__(self, file):
        """ Init the class object """
        self.file = file
        self.queue = None

    def run(self, queue):

        meta_data = {}
        file = self.file  # need to adopt the code below, to remove this line
        _objects = list(rtfobj.rtf_iter_objects(self.file))
        output = []

        if _objects:
            logger.debug(f"Enumerating document objects: {file}")
            for offset, orig_len, data in _objects:
                meta_data["filename"] = os.path.basename(file)
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

                yscanner = yarascan("agents/rules/CVE-2017-11882.yr")
                ole_yarasig = ""
                for sig in yscanner.scan_buffer(data):
                    ole_yarasig += sig.rule + ","
                if ole_yarasig[-1:] == ",":
                    ole_yarasig = ole_yarasig[:-1]

                meta_data["ole_yara_sig"] = ole_yarasig

                matched_strings = ""
                matched_strings = self.regex_scan(unique_strings)
                meta_data["ole_regex_strings"] = matched_strings

                output.append(meta_data.copy())
                meta_data.clear()
            logger.debug(f"{len(_objects)} objects found in: {self.file}")
        else:
            logger.warning(f"Unsupported file: {file}")
            return None

        print(output)
        queue.task_done()

        test = ""
        #return output


    def regex_scan(self, strings):
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

