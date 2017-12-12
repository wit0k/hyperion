import threading
import logging

logger = logging.getLogger('hyperion')

class task_manager(object):

    max_tasks_count = 10

    def __init__(self):
        self.lock = threading.Lock()
        self.tasks = []

    def close_task(self, taskmgr, task_obj):
        with self.lock:
            try:
                taskmgr.tasks.remove(task_obj)
                logger.debug(f"Task-{task_obj.id} removed from the queue successfully")
            except Exception:
                logger.warning(f"The Task-{task_obj.id} was not found in the queue")

    def execute_tasks(self):

        for task in self.tasks:
            try:
                task.thread.setDaemon(True)
                thread = task.run()
            except Exception:
                logger.error(f"Unable to run Thread-{task.name} - Error: {Exception.with_traceback()}")

        for task in self.tasks:
            task.thread.join()

    def count_tasks(self):
        with self.lock:
            return len(self.tasks)

    def create_task(self, taskmgr, func_handler, func_param=(), task_name=""):
        logger.debug(f"Creating new task (task_name: {task_name}, func_param: {func_param})")
        task = _task(taskmgr, func_handler, func_param, task_name)
        task.thread._args = (func_param, task,)
        task.params = (func_param, task,)
        self.tasks.append(task)
        return task


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

    def close(self, test):
        self.taskmgr.close_task(self.taskmgr, test)


