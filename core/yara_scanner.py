import yara
import os
import logging

logger = logging.getLogger('hyperion')

all_rules = {
                "rtf": {
                    '1':'/repos/hyperion/rules/CVE-2017-11882.yr',
                    '2':'/repos/hyperion/rules/CVE-2018-0802.yr'
                    }
            }


class yara_scanner(object):

    def __init__(self, file_type):
        """ Init the object """
        self.compiled_rules = None
        self.rules = None
        self.file_type = file_type

        if file_type:
            self.rules = self._get_rule_set(file_type)
            if self.rules:
                self.compiled_rules = self._compile_rules(self.rules)
        else:
            logger.warning('Failed to initialize the scanner object')
            return None

    def _get_rule_set(self, file_type):
        try:
            return all_rules[file_type]
        except KeyError:
            return None

    def _compile_rules(self, rules):
        if self.rules:
            logger.debug(f"Compiling rules: \n {rules}")
            return yara.compile(filepaths=rules)
        else:
            return None

    def scan_buffer(self, buffer):

        if self.compiled_rules:
            result_match = self.compiled_rules.match(data=buffer)
            if result_match:
                str_result = ""
                for item in result_match:
                    str_result += str(item) + " "
                return str_result
        else:
            logger.error("Yara scanner not initialized")
            return None

