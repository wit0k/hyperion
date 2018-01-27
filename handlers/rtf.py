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
                     "ole_regex_strings", "ole_strings"]

    def __init__(self, file):
        """ Init the class object """
        self.file = file

    """ Main module functions """
    def run(self, task, param=None):

        """ Initialize variables """
        task_data = collections.OrderedDict()
        _object = collections.OrderedDict()
        output = []
        file_buffer = ""
        file_buffer_stripped = ""
        handler = None

        """ Scan the file content """
        task_data["file_sig"] = ""
        with open(self.file, 'rb') as file_content:
            file_buffer = file_content.read()
            task_data["file_sig"] = task.scanner["yara"].scan_buffer(file_buffer)

            # Scan stripped file content if previous match was not found
            if not task_data["file_sig"]:
                try:
                    file_buffer_stripped = self._strip_keycodes(file_buffer.decode("utf8"))
                    task_data["file_sig"] = task.scanner["yara"].scan_buffer(file_buffer_stripped)
                except UnicodeDecodeError:
                    logger.warning(f"UnicodeDecodeError: Failed to decode -> {self.file}")

        """ Get the right handler by file_sig """
        handler = self._get_handler(task_data["file_sig"])
        if handler:
            if file_buffer_stripped:
                handler(self, file_buffer_stripped, task_data)
            else:
                handler(self, file_buffer, task_data)

        """ Get info about all objects available """
        _objects = list(rtfobj.rtf_iter_objects(self.file))

        task_data["obj_count"] = len(_objects)

        if _objects:
            for offset, orig_len, data in _objects:
                _object["obj_offset"] = '0x%08X' % offset
                try:
                    _oleobj = oleobj.OleObject()
                    _oleobj.parse(data)
                    _object["ole_type"] = _oleobj.class_name
                    _object["ole_size"] = _oleobj.data_size
                except Exception:
                    _object["ole_type"] = ""
                    _object["ole_size"] = ""

                _object["obj_size"] = len(data)
                _object["obj_sig"] = str(data[:self.obj_sig_len])

                try:
                    unique_strings = ""
                    data_str = data.decode(errors='ignore')
                    unique_strings = "\r".join(list(set(re.findall("[^\x00-\x1F\x7F-\xFF]{3,}", data_str))))
                except Exception:
                    unique_strings = ""

                _object["ole_strings"] = unique_strings

                """ Scan the data object content """
                ole_yarasig = ""
                ole_yarasig = task.scanner["yara"].scan_buffer(data)
                _object["ole_yara_sig"] = ole_yarasig

                matched_strings = ""
                matched_strings = task.scanner["regex"].ioc_scan(unique_strings)
                _object["ole_regex_strings"] = matched_strings

                output.append(_object.copy())
                _object.clear()

        else:
            logger.warning(f"No objects found. File: {self.file}")

        """ Properly close the task before returning from the function"""
        task_data["objects"] = output
        self.end(task,  task_data)


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





