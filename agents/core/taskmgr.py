import threading
import logging
from queue import Queue, Empty
logger = logging.getLogger('hyperion')
import time

logger = logging.getLogger('hyperion')
MONITOR_THREAD_NAME = "TaskMgr.Tasks.Handler"
MAX_SIMULTANEOUS_TASKS_COUNT = 10
SYSTEM_TASK_SLEEP_TIME = 100/1000.0

class task_manager(object):


    tasks = Queue(maxsize=MAX_SIMULTANEOUS_TASKS_COUNT)
    all_tasks = Queue()

    def __init__(self):

        self.complete = False

        """ Setup system daemon Threads """
        t_update_tasks =  threading.Thread(name=MONITOR_THREAD_NAME, target=self.update_tasks_queue)
        #t_run_tasks = threading.Thread(name="TaskMgr.Queue.Handler", target=self.run_tasks)

        """ Start Daemon threads which would handle the thread execution """
        t_update_tasks.daemon = True
        t_update_tasks.start()
        #t_run_tasks.start()

    def update_tasks_queue(self):
        """ ... """

        print(f"Remaining Tasks: {self.all_tasks.unfinished_tasks}")

        logger.debug("Start monitoring the Task queue...")
        while self.complete is False:
            """ Insert tasks in the queue up to  MAX_SIMULTANEOUS_TASKS_COUNT """

            if self.tasks.unfinished_tasks == 0 and self.all_tasks.unfinished_tasks == 0:
                #print(f"Waiting for tasks ... (TaskMgr Complete: {self.complete})")
                time.sleep(SYSTEM_TASK_SLEEP_TIME)

            elif self.tasks.unfinished_tasks < MAX_SIMULTANEOUS_TASKS_COUNT and self.all_tasks.unfinished_tasks != 0:
                print(f"Current Tasks: {self.tasks.unfinished_tasks}")
                """ Pull a new task """
                try:
                    task = self.all_tasks.get_nowait()
                    """ Mark the new task for execution """
                    self.tasks.put(task)

                    """ Decrease the count of remaining tasks (unfinished_tasks - 1) """
                    self.all_tasks.task_done()
                except Empty:
                    test = ""

            else:
                """ Execute the tasks """
                #time.sleep(SYSTEM_TASK_SLEEP_TIME)
                print(f"Current Tasks: {self.tasks.unfinished_tasks}")
                print(f"Remaining Tasks: {self.all_tasks.unfinished_tasks}")
                print(f"TaskMgr Complete: {self.complete}")

                logger.debug("Running Tasks...")
                for i in range(0, MAX_SIMULTANEOUS_TASKS_COUNT):
                    try:
                        task = self.tasks.get_nowait()
                        logger.debug(f"Execute Task ID: {task.id} - File: {task.properties['file_path']}")
                        task.run()
                    except Empty:
                        test = ""

                print("C")

                test = ""
                if self.complete:
                    logger.debug(f"No more tasks to monitor. Exit")
                    break
            print("-------------------------")
        print("Oupssssssss!!!!!!")


    def run_tasks(self):
        """ Thread which monitors the tasks and execute them """

        logger.debug("Ready to execute Tasks...")
        while self.complete is False:
            if self.tasks.unfinished_tasks < MAX_SIMULTANEOUS_TASKS_COUNT:
                task = self.tasks.get()
                logger.debug(f"Execute Task ID: {task.id} - File: {task.properties['file_path']}")
                task.run()
            else:
                time.sleep(SYSTEM_TASK_SLEEP_TIME)

        if self.complete:
            logger.debug(f"No more tasks to execute. Exit")

    def add_task(self, task):
        self.all_tasks.put(task)


    def new_task(self, func_handler, func_param=(), task_name="", task_type="", properties={}):
        task = _task(self, func_handler, func_param, task_name, properties, task_type)
        self.add_task(task)

    def stop(self):

        while self.complete is False:

            print ("Stoping ....")
            if self.all_tasks.unfinished_tasks == 0 and self.tasks.unfinished_tasks == 0:
                self.complete = True
                logger.debug("Stopping TaskMgr Monitor threads...")
                for thread in threading.enumerate():
                    if thread.name == MONITOR_THREAD_NAME:
                        logger.debug(f"Daemon thread: {MONITOR_THREAD_NAME} remain started...")

class _task():

    def __init__(self, taskmgr, func_handler, func_param=(), task_name="", properties={}, task_type=""):

        self.taskmgr = taskmgr
        self.id = properties["id"]
        self.thread = None
        self.thread_id = None
        self.handler = None
        self.function_handler = None
        self.name = task_name
        self.type = task_type
        self.properties = properties
        self.result = []

        if func_param:
            self.thread = threading.Thread(name=task_name, target=func_handler, args=func_param)
        else:
            self.thread = threading.Thread(name=task_name, target=func_handler)


    def get_output(self, output):
        self.result = output

    def run(self):
        try:
            self.thread.start()
            self.thread_id = self.thread.ident
        except Exception:
            logger.error(Exception)
            return None


