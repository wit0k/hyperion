import logging
from .core.agent import *
from .handlers.rtf import *
logger = logging.getLogger('hyperion')

class fileagent(agent):

    name = "fileagent"

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

    def open_task(self, files):

        if not isinstance(files, list):
            files = [files]
        """ Create tasks """
        for file in files:
            self.taskmgr.create_task(self.taskmgr, self.process_task, file, "fileagent")

        """ Execute Tasks """
        self.taskmgr.execute_tasks()

    def process_task(self, file, task_obj):

        item = {"file_id": "", "file_path": "", "file_type": ""}

        if os.path.isfile(file):
            logger.debug(f"Process file: {file}")
            item["file_type"] = self.file_type(file)
            logger.debug(f'File type: {item["file_type"]}')
            item["file_id"] = self.md5(file)
            item["file_path"] = file
            logger.debug(f'File md5: {item["file_id"]}')
            handler = self.handlers_list[item["file_type"]]
            logger.debug(f"File handler: {handler}")
            logger.debug(f'Execute file handler: {handler.name}({file})')
            result = handler(file, task_obj)

            if result.output:
                item["result"] = result.output.copy()
                self.results.append(item.copy())
                logger.debug(item)
                logger.debug("Clear the result buffer")
                result.output.clear()
        else:
            logger.debug(f"Unable to locate file: {file}")

    def __init__(self, taskmgr, files):
        logger.debug(f"Initialize {self.name}")
        self.results = []
        self.taskmgr = taskmgr
        self.open_task(files)


