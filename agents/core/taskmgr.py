import threading
import logging
import time

logger = logging.getLogger('hyperion')

class task_manager(object):

    max_tasks_count = 10

    def __init__(self):
        self.lock = threading.Lock()
        self.tasks = []
        self.active_tasks = []

    def count_active_tasks(self):
        with self.lock:
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
            except Exception:
                logger.warning(f"The Task-{task_obj.id} was not found in the queue")

    def create_task(self, taskmgr, func_handler, func_param=(), task_name=""):
        logger.debug(f"Creating new task (task_name: {task_name}, func_param: {func_param})")
        task = _task(taskmgr, func_handler, func_param, task_name)
        task.thread._args = (func_param, task)
        task.params = (func_param, task)
        self.tasks.append(task)
        return task

    def execute_task(self, task):
        self.thread = task.run()

    def _wait(self, active_tasks_count):
        _continue = False
        while active_tasks_count >= self.max_tasks_count:
            logger.debug(f"Active Tasks: {active_tasks_count} - Waiting 1 second for free slot in Tasks queue...")
            time.sleep(1)
            active_tasks_count = self.count_active_tasks()
            _continue = True

        if _continue:
            logger.debug(f"Active Tasks: {active_tasks_count} - Release the queue")

        return True

    def execute_tasks(self):
        for task in self.tasks:
            try:
                #task.thread.setDaemon(True)
                if self._wait(self.count_active_tasks()):
                    self.thread = task.run()
                    self.active_tasks.append(task)

                    #logger(f"Started Task-{task.id}")

            except Exception:
                logger.error(f"Unable to run Thread-{task.name} - Error: {Exception}")

        #for task in self.tasks:
            #task.thread.join()

class _task():

    def __init__(self, taskmgr, func_handler, func_param=(), task_name=""):
        self.taskmgr = taskmgr
        self.id = None
        self.thread = None
        self.name = task_name
        self.params = func_param

        if self.params:
            self.thread = threading.Thread(name=task_name, target=func_handler, args=self.params)
        else:
            self.thread = threading.Thread(name=task_name, target=func_handler)

    def run(self):
        try:
            self.thread.start()
            self.id = self.thread.ident
            return self.thread
        except Exception:
            logger.error(Exception)
            return None

    def close(self):
        self.taskmgr.close_task(self)


