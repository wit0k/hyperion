import yara
import os
import logging

logger = logging.getLogger('hyperion')

all_rules = {
                "rtf": {
                    '1':'/repos/hyperion/agents/rules/CVE-2017-11882.yr',
                    '2':'/repos/hyperion/agents/rules/CVE-2018-0802.yr'
                    }
            }


class scanner(object):


    def __init__(self, file_type):
        """ Initialise the rule sets accordingly, by file type """

        """ http://yara.readthedocs.io/en/v3.7.1/yarapython.html """
        self.file_type = file_type
        self.rules = self._get_rule_set()
        self.scanner = self._compile_rules()

        if not self.scanner:
            logger.error("Failed to initialize Yara scanner")

    def _get_rule_set(self):
        try:
            return all_rules[self.file_type]
        except KeyError:
            return None

    def _compile_rules(self):
        if self.rules:
            logger.debug(f"Compiling rules: \n {self.rules}")
            return yara.compile(filepaths=self.rules)
        else:
            return None

    def scan_buffer(self, buffer):
        if self.scanner:
            result_match = self.scanner.match(data=buffer)
            if result_match:
                str_result = ""
                for item in result_match:
                    str_result += str(item) + " "
                return str_result

        else:
            logger.error("Yara scanner not initialized")
            return None

    def scan_file(self, file):
        if self.scanner:
            return self.scanner.match(file)
        else:
            logger.error("Yara scanner not initialized")
            return None


