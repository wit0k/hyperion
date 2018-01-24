import magic
import platform as _os
import logging

MAGIC_FILE_PATH_LINUX = '/etc/magic'
MAGIC_FILE_PATH_MAC = '/usr/local/Cellar/libmagic/5.29/share/misc/magic'

logger = logging.getLogger('hyperion')

class file_type(object):

    file_types = {
        "Apple Desktop Services Store": None,
        "Rich Text Format data, version 1, ANSI": "rtf"
    }

    def __init__(self, file_path, GetMIMEType=False):

        self.type = None

        if 'Darwin' in _os.platform():
            MAGIC_FILE_PATH = MAGIC_FILE_PATH_MAC
        elif 'Linux' in _os.platform():
            MAGIC_FILE_PATH = MAGIC_FILE_PATH_LINUX

        obj_magic = magic.Magic(magic_file=MAGIC_FILE_PATH, mime=GetMIMEType)
        file_type = obj_magic.from_file(file_path)
        if file_type:
            try:
                self.type = self.file_types[file_type]
            except KeyError:
                self.type = None
        else:
            logger.error(f"Unable to determine the file type: {file_path}")

