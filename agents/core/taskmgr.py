import threading
import logging

logger = logging.getLogger('hyperion')

class task_manager(object):

    max_tasks_count = 10

    def __init__(self):
        self.tasks = []

    def remove_task(self, task_id):
        for task in self.tasks:
            if task.id == task_id:
                logging.debug(f"Removing task: {task_id} from tasks queue")
                self.tasks.remove(task)

    def execute_tasks(self):
        for task in self.tasks:
            try:
                task.thread.setDaemon(True)
                task.run()
            except Exception:
                logger.error(f"Unable to run Thread-{task.name} - Error: {Exception.with_traceback()}")

        for task in self.tasks:
            task.thread.join()



    def count_tasks(self):
        return len(self.tasks)

    def create_task(self, func_handler, func_param=(), task_name=""):
        logger.debug(f"Creating new task (task_name: {task_name}, func_param: {func_param})")

        task = _task(func_handler, func_param, task_name)
        self.tasks.append(task)
        return task


class _task():

    def __init__(self, func_handler, func_param=(), task_name=""):
        self.id = None
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
        except Exception:
            logger.error(Exception)

