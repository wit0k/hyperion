import yara
import os
class yarascan(object):
    def __init__(self, rules):
        self.rules = rules

    def scan_buffer(self, buffer):
        rule = yara.compile(filepath=self.rules)
        return rule.match(data=buffer)