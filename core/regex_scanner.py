import re

class regex_scanner(object):

    def __init__(self, file_type):

        """ Taken from olevba and re-search (Didier Stevens) """
        self.SCHEME = r'\b(?:http|ftp)s?'
        self.TLD = r'(?:xn--[a-zA-Z0-9]{4,20}|[a-zA-Z]{2,20})'
        self.DNS_NAME = r'(?:[a-zA-Z0-9\-\.]+\.' + self.TLD + ')'
        self.NUMBER_0_255 = r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])'
        self.IPv4 = r'(?:' + self.NUMBER_0_255 + r'\.){3}' + self.NUMBER_0_255
        self.SERVER = r'(?:' + self.IPv4 + '|' + self.DNS_NAME + ')'
        self.PORT = r'(?:\:[0-9]{1,5})?'
        self.SERVER_PORT = self.SERVER + self.PORT
        self.URL_PATH = r'(?:/[a-zA-Z0-9\-\._\?\,\'/\\\+&%\$#\=~]*)?'  # [^\.\,\)\(\s"]
        self.URL_RE = self.SCHEME + r'\://' + self.SERVER_PORT + self.URL_PATH
        self.re_url = re.compile(self.URL_RE)

        self.RE_PATTERNS = {
            'url_v1': re.compile(self.URL_RE),
            'url_v2': re.compile(
                r'[a-zA-Z]+://[-a-zA-Z0-9.]+(?:/[-a-zA-Z0-9+&@#/%=~_|!:,.;]*)?(?:\?[a-zA-Z0-9+&@#/%=~_|!:,.;]*)?'),
            'ipv4_v1': re.compile(self.IPv4),
            'ipv4_v2': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'),
            'email_v1': re.compile(r'(?i)\b[A-Z0-9._%+-]+@' + self.SERVER + '\b'),
            'email_v2': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}'),
            'domain': re.compile(r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)'),
            "exe_name": re.compile(
                r"(?i)\b\w+\.(EXE|PIF|GADGET|MSI|MSP|MSC|VBS|VBE|VB|JSE|JS|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR|HTA|CPL|CLASS|JAR|PS1XML|PS1|PS2XML|PS2|PSC1|PSC2|SCF|LNK|INF|REG)\b"),
            'btc': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'file_path': re.compile(r'((?:(?:[A-Za-z]:)|\/home|(%[A-Za-z]+%\\))[^\.]+\.[A-Za-z]{2,8})')
        }

    def ioc_scan(self, strings):

        results = []
        found = []
        for pattern_type, pattern_re in self.RE_PATTERNS.items():
            for match in pattern_re.finditer(strings):
                value = match.group()
                if value not in found:
                    results.append({pattern_type: value})
                    found.append({pattern_type: value})
        return results