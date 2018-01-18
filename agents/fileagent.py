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

            """ Set task properties """
            properties = {}
            properties["file_path"] = file
            properties["file_hash"] = self.md5(file)
            properties["id"] = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + properties["file_hash"].upper()
            properties["file_type"] = self.file_type(file)

            """ Get the Handler """
            handler = self.handlers_list[properties["file_type"]](file)

            if handler:
                self.taskmgr.new_task(func_handler=handler.run, func_param=(self.taskmgr.tasks,), task_name="",
                                         task_type=self.name, properties=properties)


        # it will resume when all items have been processed (meaning that a task_done() call was received for every item that had been put() into the queue)
        self.taskmgr.all_tasks.join()

        print("---------------------- self.taskmgr.all_tasks.join() --------------------------------")
        print(f"Current Running Tasks: {self.taskmgr.tasks.unfinished_tasks}")
        print(f"Tasks marked for execution: {self.taskmgr.tasks.qsize()}")
        print(f"Remaining Tasks: {self.taskmgr.all_tasks.unfinished_tasks}")


        """ For some reason the self.taskmgr.tasks.join() does not work properly, hence doing it manually  """
        execute = True
        while execute:
            running_threads = ""
            for thread in threading.enumerate():
                running_threads += thread.name + " | "

            if "TASK-" in running_threads:
                print(running_threads)
                time.sleep(1)
            else:
                logger.info("No more tasks running!")
                self.taskmgr.tasks.mutex.acquire()
                self.taskmgr.tasks.queue.clear()
                self.taskmgr.tasks.all_tasks_done.notify_all()
                self.taskmgr.tasks.unfinished_tasks = 0
                self.taskmgr.tasks.mutex.release()
                self.taskmgr.complete = True
                execute = False


        self.taskmgr.stop()



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

