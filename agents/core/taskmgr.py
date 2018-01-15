import threading
import logging
import time

logger = logging.getLogger('hyperion')

class task_manager(object):

    max_tasks_count = 10
    tasks = []

    def __init__(self):
        self.lock = threading.Lock()
        self.system_tasks = []
        self.active_tasks = []

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

    def create_task(self, func_handler, func_param=(), task_name="", task_type="", properties={}):
        logger.debug(f"Creating new task (task_name: {task_name}")
        task = _task(self, func_handler, func_param, task_name, properties, task_type)
        self.tasks.append(task)
        return task

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
        self.id = None
        self.thread = None
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
            self.id = self.thread.ident
            return self.id
        except Exception:
            logger.error(Exception)
            return None

    def close(self):
        self.taskmgr.close_task(self)


