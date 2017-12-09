import threading
import logging

logger = logging.getLogger('hyperion')

class task_manager(object):

    def __init__(self):
        self.tasks = []

    def create_task(self, func_handler, func_param=(), task_name=""):
        logger.debug(f"Creating new task (task_name: {task_name}, func_param: {func_param})")
        task = _task(func_handler, func_param, task_name)
        self.tasks.append(task)
        return task


class _task():

    def __init__(self, func_handler, func_param=(), task_name=""):
        self.name = task_name
        self.params = func_param

        if self.params:
            self.thread = threading.Thread(name=task_name, target=func_handler, args=self.params)
        else:
            self.thread = threading.Thread(name=task_name, target=func_handler)

    def run(self):
        try:
            self.thread.start()
        except Exception:
            logger.error(Exception)

