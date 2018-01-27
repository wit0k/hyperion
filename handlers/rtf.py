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
        task_data["body_ioc"] = task.scanner["regex"].ioc_scan(file_buffer.decode("utf8"))
        task_data["body_text"] = self._striprtf(file_buffer.decode("utf8"))

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

    # Taken from: https://gist.githubusercontent.com/gilsondev/7c1d2d753ddb522e7bc22511cfb08676/raw/163ef3ee9893109f10cccf4b51d1d077ada296fa/extract_rtf.py
    def _striprtf(self, text):
        pattern = re.compile(r"\\([a-z]{1,32})(-?\d{1,10})?[ ]?|\\'([0-9a-f]{2})|\\([^a-z])|([{}])|[\r\n]+|(.)", re.I)
        # control words which specify a "destionation".
        destinations = frozenset((
            'aftncn', 'aftnsep', 'aftnsepc', 'annotation', 'atnauthor', 'atndate', 'atnicn', 'atnid',
            'atnparent', 'atnref', 'atntime', 'atrfend', 'atrfstart', 'author', 'background',
            'bkmkend', 'bkmkstart', 'blipuid', 'buptim', 'category', 'colorschememapping',
            'colortbl', 'comment', 'company', 'creatim', 'datafield', 'datastore', 'defchp', 'defpap',
            'do', 'doccomm', 'docvar', 'dptxbxtext', 'ebcend', 'ebcstart', 'factoidname', 'falt',
            'fchars', 'ffdeftext', 'ffentrymcr', 'ffexitmcr', 'ffformat', 'ffhelptext', 'ffl',
            'ffname', 'ffstattext', 'field', 'file', 'filetbl', 'fldinst', 'fldrslt', 'fldtype',
            'fname', 'fontemb', 'fontfile', 'fonttbl', 'footer', 'footerf', 'footerl', 'footerr',
            'footnote', 'formfield', 'ftncn', 'ftnsep', 'ftnsepc', 'g', 'generator', 'gridtbl',
            'header', 'headerf', 'headerl', 'headerr', 'hl', 'hlfr', 'hlinkbase', 'hlloc', 'hlsrc',
            'hsv', 'htmltag', 'info', 'keycode', 'keywords', 'latentstyles', 'lchars', 'levelnumbers',
            'leveltext', 'lfolevel', 'linkval', 'list', 'listlevel', 'listname', 'listoverride',
            'listoverridetable', 'listpicture', 'liststylename', 'listtable', 'listtext',
            'lsdlockedexcept', 'macc', 'maccPr', 'mailmerge', 'maln', 'malnScr', 'manager', 'margPr',
            'mbar', 'mbarPr', 'mbaseJc', 'mbegChr', 'mborderBox', 'mborderBoxPr', 'mbox', 'mboxPr',
            'mchr', 'mcount', 'mctrlPr', 'md', 'mdeg', 'mdegHide', 'mden', 'mdiff', 'mdPr', 'me',
            'mendChr', 'meqArr', 'meqArrPr', 'mf', 'mfName', 'mfPr', 'mfunc', 'mfuncPr', 'mgroupChr',
            'mgroupChrPr', 'mgrow', 'mhideBot', 'mhideLeft', 'mhideRight', 'mhideTop', 'mhtmltag',
            'mlim', 'mlimloc', 'mlimlow', 'mlimlowPr', 'mlimupp', 'mlimuppPr', 'mm', 'mmaddfieldname',
            'mmath', 'mmathPict', 'mmathPr', 'mmaxdist', 'mmc', 'mmcJc', 'mmconnectstr',
            'mmconnectstrdata', 'mmcPr', 'mmcs', 'mmdatasource', 'mmheadersource', 'mmmailsubject',
            'mmodso', 'mmodsofilter', 'mmodsofldmpdata', 'mmodsomappedname', 'mmodsoname',
            'mmodsorecipdata', 'mmodsosort', 'mmodsosrc', 'mmodsotable', 'mmodsoudl',
            'mmodsoudldata', 'mmodsouniquetag', 'mmPr', 'mmquery', 'mmr', 'mnary', 'mnaryPr',
            'mnoBreak', 'mnum', 'mobjDist', 'moMath', 'moMathPara', 'moMathParaPr', 'mopEmu',
            'mphant', 'mphantPr', 'mplcHide', 'mpos', 'mr', 'mrad', 'mradPr', 'mrPr', 'msepChr',
            'mshow', 'mshp', 'msPre', 'msPrePr', 'msSub', 'msSubPr', 'msSubSup', 'msSubSupPr', 'msSup',
            'msSupPr', 'mstrikeBLTR', 'mstrikeH', 'mstrikeTLBR', 'mstrikeV', 'msub', 'msubHide',
            'msup', 'msupHide', 'mtransp', 'mtype', 'mvertJc', 'mvfmf', 'mvfml', 'mvtof', 'mvtol',
            'mzeroAsc', 'mzeroDesc', 'mzeroWid', 'nesttableprops', 'nextfile', 'nonesttables',
            'objalias', 'objclass', 'objdata', 'object', 'objname', 'objsect', 'objtime', 'oldcprops',
            'oldpprops', 'oldsprops', 'oldtprops', 'oleclsid', 'operator', 'panose', 'password',
            'passwordhash', 'pgp', 'pgptbl', 'picprop', 'pict', 'pn', 'pnseclvl', 'pntext', 'pntxta',
            'pntxtb', 'printim', 'private', 'propname', 'protend', 'protstart', 'protusertbl', 'pxe',
            'result', 'revtbl', 'revtim', 'rsidtbl', 'rxe', 'shp', 'shpgrp', 'shpinst',
            'shppict', 'shprslt', 'shptxt', 'sn', 'sp', 'staticval', 'stylesheet', 'subject', 'sv',
            'svb', 'tc', 'template', 'themedata', 'title', 'txe', 'ud', 'upr', 'userprops',
            'wgrffmtfilter', 'windowcaption', 'writereservation', 'writereservhash', 'xe', 'xform',
            'xmlattrname', 'xmlattrvalue', 'xmlclose', 'xmlname', 'xmlnstbl',
            'xmlopen',
        ))
        # Translation of some special characters.
        specialchars = {
            'par': '\n',
            'sect': '\n\n',
            'page': '\n\n',
            'line': '\n',
            'tab': '\t',
            'emdash': '\u2014',
            'endash': '\u2013',
            'emspace': '\u2003',
            'enspace': '\u2002',
            'qmspace': '\u2005',
            'bullet': '\u2022',
            'lquote': '\u2018',
            'rquote': '\u2019',
            'ldblquote': '\201C',
            'rdblquote': '\u201D',
        }
        stack = []
        ignorable = False  # Whether this group (and all inside it) are "ignorable".
        ucskip = 1  # Number of ASCII characters to skip after a unicode character.
        curskip = 0  # Number of ASCII characters left to skip
        out = []  # Output buffer.
        for match in pattern.finditer(text):
            word, arg, hex, char, brace, tchar = match.groups()
            if brace:
                curskip = 0
                if brace == '{':
                    # Push state
                    stack.append((ucskip, ignorable))
                elif brace == '}':
                    # Pop state
                    ucskip, ignorable = stack.pop()
            elif char:  # \x (not a letter)
                curskip = 0
                if char == '~':
                    if not ignorable:
                        out.append('\xA0')
                elif char in '{}\\':
                    if not ignorable:
                        out.append(char)
                elif char == '*':
                    ignorable = True
            elif word:  # \foo
                curskip = 0
                if word in destinations:
                    ignorable = True
                elif ignorable:
                    pass
                elif word in specialchars:
                    out.append(specialchars[word])
                elif word == 'uc':
                    ucskip = int(arg)
                elif word == 'u':
                    c = int(arg)
                    if c < 0: c += 0x10000
                    if c > 127:
                        out.append(chr(c))  # NOQA
                    else:
                        out.append(chr(c))
                    curskip = ucskip
            elif hex:  # \'xx
                if curskip > 0:
                    curskip -= 1
                elif not ignorable:
                    c = int(hex, 16)
                    if c > 127:
                        out.append(chr(c))  # NOQA
                    else:
                        out.append(chr(c))
            elif tchar:
                if curskip > 0:
                    curskip -= 1
                elif not ignorable:
                    out.append(tchar)
        return ''.join(out)





