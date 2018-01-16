import logging
import threading
import datetime
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

    def process_files(self):
        """ Creates a task for each file with appropriate handler  """

        for file in self.files:

            file_type = self.file_type(file)
            file_hash = self.md5(file)

            properties = {}
            properties["file_path"] = file
            properties["file_hash"] = file_hash
            properties["id"] = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + properties["file_hash"].upper()
            properties["file_type"] = file_type

            handler = self.handlers_list[file_type](file)

            if handler:
                self.taskmgr.new_task(func_handler=handler.run, func_param=(self.taskmgr.tasks,), task_name="",
                                         task_type=self.name, properties=properties)


        # it will resume when all items have been processed (meaning that a task_done() call was received for every item that had been put() into the queue)
        self.taskmgr.tasks.join()

        self.taskmgr.stop()

        test = ""
        """ Working single thread code
        for file in self.files:
            if os.path.isfile(file):
                # Check file type
                file_type = self.file_type(file)

                # Obtain file handler
                handler = self.handlers_list[file_type](file)

                # Adjust task properties
                properties = {}
                properties["file_type"] = file_type
                properties["file_hash"] = self.md5(file)
                properties["file_path"] = file

                if handler:
                    self.results.append(handler.run())
                else:
                    logger.warning("File handler not found! -> %s" % file)
        """
        test = ""

    def print_results(self):

        for item in self.results:
            logger.error(item)

    def __init__(self, taskmgr, files):

        logger.debug(f"Initialize {self.name}")

        self.results = []
        self.taskmgr = taskmgr

        """ Convert the list """
        if not isinstance(files, list):
            self.files = [files]
        else:
            self.files = files

