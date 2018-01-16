import threading
import logging
from queue import Queue
logger = logging.getLogger('hyperion')
import time

logger = logging.getLogger('hyperion')
MAX_SIMULTANEOUS_TASKS_COUNT = 10

class task_manager(object):


    tasks = Queue(maxsize=MAX_SIMULTANEOUS_TASKS_COUNT)
    all_tasks = Queue()

    def __init__(self):

        self.complete = False

        #self.lock = threading.Lock()
        self.system_tasks = []
        self.active_tasks = []

        """ Setup system daemon Threads """
        t_update_tasks =  threading.Thread(name="update_tasks_queue", target=self.update_tasks_queue)
        t_run_tasks = threading.Thread(name="run_tasks", target=self.run_tasks)

        """ Start Daemon threads which would handle the thread execution """
        t_update_tasks.start()
        t_run_tasks.start()

    def update_tasks_queue(self):
        """ Make sure that the amount of Tasks to execute is MAX_SIMULTANEOUS_TASKS_COUNT """
        logger.debug("Start monitoring the Task queue...")
        while True:
            if self.tasks.qsize() < MAX_SIMULTANEOUS_TASKS_COUNT:
                try:
                    task = self.all_tasks.get()
                    self.tasks.put(task)
                except Exception:
                    test = ""

    def run_tasks(self):
        """ Daemon thread which monitors the tasks and execute them """

        execute = True
        logger.debug("Ready to execute Tasks...")
        while execute:
            task = self.tasks.get()
            logger.debug(f"Execute Task ID: {task.id}")
            task.run()

            if self.complete:
                logger.debug(f"No more tasks to execute. Exit")
                break

    def add_task(self, task):
        self.all_tasks.put(task)

    def new_task(self, func_handler, func_param=(), task_name="", task_type="", properties={}):
        task = _task(self, func_handler, func_param, task_name, properties, task_type)
        self.add_task(task)

        #self.tasks.append(task)
        #return task

    def stop(self):

        while self.complete:
            if self.all_tasks.qsize() == 0 and self.tasks.unfinished_tasks == 0:
                self.complete = True
                exit(-1)
            else:
                time.sleep(1)



    def count_active_tasks(self):
            _len = len(self.active_tasks)

            if _len:
                return _len
            else:
                return 0

    def close_task(self, task_obj):
        with self.lock:
            try:
                self.tasks.remove(task_obj)
                self.active_tasks.remove(task_obj)
                logger.debug(f"Task-{task_obj.id} removed from the queue successfully")
                logger.debug(f"Task-{task_obj.id} Active Tasks: {self.count_active_tasks()}")
            except Exception:
                logger.warning(f"The Task-{task_obj.id} was not found in the queue")

    def execute_task(self, task):
        task.thread.setDaemon(True)
        task.thread = task.run()

    def _wait(self, active_tasks_count):
        pass
        """
        _continue = False
        "while active_tasks_count >= self.max_tasks_count:
            logger.debug(f"Active Tasks: {active_tasks_count} - Waiting 1 second for free slot in Tasks queue...")
            active_tasks_count = self.count_active_tasks()
            _continue = True

        if _continue:
            logger.debug(f"Active Tasks: {active_tasks_count} - Release the queue")
        """
        return True

    def execute_tasks(self):
        for task in self.tasks:
            try:
                task.thread.setDaemon(True)
                if self._wait(self.count_active_tasks()):
                    task.thread = task.run()
                    self.active_tasks.append(task)
                    logger.debug(f"Started Task-{task.id}")

            except Exception:
                logger.error(f"Unable to run Thread-{task.name} - Error: {Exception}")

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

    def close(self):
        self.taskmgr.close_task(self)


