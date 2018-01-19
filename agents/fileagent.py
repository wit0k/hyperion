import logging
import time
import hashlib
import datetime
from .core.agent import *
from .handlers.rtf import *
from .core.scanner import *

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

        logger.info(f"Processing [{len(self.files)}] files")
        for file in self.files:

            """ Set task properties """
            task_properties = {}
            task_properties["file_path"] = file
            task_properties["file_hash"] = self.md5(file)
            task_properties["id"] = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + task_properties["file_hash"].upper()
            task_properties["file_type"] = self.file_type(file)

            """ Get the Scanner object """
            task_properties["scanner"] = scanner(task_properties["file_type"])

            """ Get the Handler """
            handler = self.handlers_list[task_properties["file_type"]](file)

            if handler:
                self.taskmgr.new_task(handler=handler, func_handler=handler.run, task_name="", task_type=self.name, properties=task_properties)

        self.taskmgr.all_tasks.join()

        """ For some reason the self.taskmgr.tasks.join() does not work properly, hence doing it manually  """
        self.taskmgr.wait_untill_processed(self.taskmgr.tasks)
        self.taskmgr.stop()



    def __init__(self, taskmgr, files):

        logger.debug(f"Initialize {self.name}")

        self.results = []
        self.taskmgr = taskmgr

        """ Convert the list """
        if not isinstance(files, list):
            self.files = [files]
        else:
            self.files = files

