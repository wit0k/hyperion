import logging
from .core.agent import *
from .handlers.rtf import *
logger = logging.getLogger('hyperion')

class fileagent(agent):

    def file_type(self, file):
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

    def prepare(self, files):

        if not isinstance(files, list):
            files = [files]

        for file in files:
            self.taskmgr.create_task(self.process, (file, ), "fileagent")

        self.taskmgr.execute_tasks()

    def process(self, file):

        if os.path.isfile(file):
            logger.debug(f"Processing file: {file}")
            logger.debug("Determine the file type")
            self.filetype = self.file_type(file)
            self.filehash = self.md5(file)
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

                    logger.debug(output_str)
                    output_str = ""
                    #print(output_str, sep=",")

                logger.debug("Clear the result buffer")
                result.output.clear()
        else:
            logger.debug(f"Unable to locate file: {file}")

    def __init__(self, taskmgr, files):
        self.taskmgr = taskmgr
        self.prepare(files)


