import logging
import time

from core.agent import *
from handlers.rtf import *
from core.yara_scanner import *
from core.file_type import *

logger = logging.getLogger('hyperion')

class fileagent(agent):

    name = "fileagent"

    def file_type(self, file):
        _file = file_type(file)
        return _file.type

    handlers_list = {
        "rtf": rtf
    }

    def execute(self):
        """ Creates a task for each file with appropriate handler  """

        loaded_scanners = {}

        logger.info(f"Processing [{len(self.files)}] files")
        for file in self.files:

            """ Set task properties """
            file_type = self.file_type(file)

            if file_type:
                if file_type in loaded_scanners.keys():
                    _scanner = loaded_scanners[file_type]
                else:
                    _scanner = yara_scanner(file_type)
                    loaded_scanners[file_type] = _scanner

                """ Get the Handler """
                handler = self.handlers_list[file_type](file)

                if handler:
                    self.taskmgr.new_task(file=file, file_type=file_type, handler=handler, func_handler=handler.run, task_name="",
                                          task_type="file", scanner=_scanner)
            else:
                logger.warning(f"Unsupported file type. File: '{file}'")

        self.taskmgr.all_tasks.join()

        """ For some reason the self.taskmgr.tasks.join() does not work properly, hence doing it manually  """
        self.taskmgr.wait_untill_processed(self.taskmgr.tasks)
        self.taskmgr.stop()

    def print(self):
        self.taskmgr.print_results()

    def __init__(self, taskmgr, files):

        logger.debug(f"Initialize {self.name}")

        self.results = []
        self.taskmgr = taskmgr

        """ Convert the list """
        if not isinstance(files, list):
            self.files = [files]
        else:
            self.files = files

