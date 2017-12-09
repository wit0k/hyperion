import logging
from .core.agent import *
from .handlers.rtf import *
logger = logging.getLogger('hyperion')

class fileagent(agent):

    def filetype(self, file):
        return "rtf"

    def md5(self, fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    handlers_list = {
        "rtf": rtf
    }

    def __init__(self, file):

        logger.debug(f"Processing file: {file}")
        logger.debug("Determine the file type")
        self.filetype = self.filetype(file)
        self.filehash = self.md5(file)

        if file:
            self.file = file
            logger.debug("Lookup the file handler")
            handler = self.handlers_list[self.filetype]
            logger.debug(f"Execute the handler: {handler.name}({self.file})")
            result = handler(self.file)

            if result.output:
                for item in result.output:
                    output_str = []

                    item["file_hash"] = self.filehash
                    for key in result.output_format:
                        try:
                            if isinstance(item[key], list):
                                output_str.append("; ".join(item[key]))
                            else:
                                output_str.append(str(item[key]))
                        except KeyError:
                            output_str.append("")

                    print(output_str, sep=",")



