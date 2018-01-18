import threading
import logging
from queue import Queue, Empty
logger = logging.getLogger('hyperion')
import time

logger = logging.getLogger('hyperion')
MONITOR_THREAD_NAME = "TaskMgr.Tasks.Handler"
MAX_SIMULTANEOUS_TASKS_COUNT = 5
SYSTEM_TASK_SLEEP_TIME = 100/1000.0

class task_manager(object):


    tasks = Queue(maxsize=MAX_SIMULTANEOUS_TASKS_COUNT)
    all_tasks = Queue()

    def __init__(self):

        self.complete = False

        """ Setup system daemon Threads """
        t_monitor_tasks_queue = threading.Thread(name=MONITOR_THREAD_NAME, target=self.monitor_tasks_queue)

        """ Start Daemon threads which would handle the thread execution """
        t_monitor_tasks_queue.daemon = True
        t_monitor_tasks_queue.start()

        logger.info("Task Manager settings:")
        logger.info(f"MONITOR_THREAD_NAME: {MONITOR_THREAD_NAME}")
        logger.info(f"MAX_SIMULTANEOUS_TASKS_COUNT: {MAX_SIMULTANEOUS_TASKS_COUNT}")
        logger.info(f"SYSTEM_TASK_SLEEP_TIME: {SYSTEM_TASK_SLEEP_TIME}")

    def monitor_tasks_queue(self):
        """ Daemon thread (TaskMgr.Tasks.Handler) handling queues:
            - Starts up to MAX_SIMULTANEOUS_TASKS_COUNT threads
         """
        logger.info("Monitoring tasks ...")
        while self.complete is False:

            # Handles initial state (before the queues get filled in)
            if self.tasks.unfinished_tasks == 0 and self.all_tasks.unfinished_tasks == 0:
                time.sleep(SYSTEM_TASK_SLEEP_TIME)

            # Insert tasks in the queue (Assumes some tasks already wait in the all_tasks queue)
            elif self.tasks.unfinished_tasks < MAX_SIMULTANEOUS_TASKS_COUNT and self.all_tasks.unfinished_tasks != 0:
                """ Pull a new task """
                try:
                    task = self.all_tasks.get_nowait()
                    """ Mark the new task for execution """
                    self.tasks.put_nowait(task)

                    """ Decrease the count of remaining tasks (unfinished_tasks - 1) """
                    self.all_tasks.task_done()
                except Empty:
                    logger.debug("All tasks queue is empty...")

            elif self.tasks.unfinished_tasks > 0 and self.all_tasks.unfinished_tasks == 0 and self.tasks.qsize() == 0:
                time.sleep(SYSTEM_TASK_SLEEP_TIME)
            else:
                """ Execute the tasks """
                current_tasks_queue_size = self.tasks.qsize()
                #print(f"Current Running Tasks: {self.tasks.unfinished_tasks}")
                #print(f"Tasks marked for execution: {current_tasks_queue_size}")
                #print(f"Remaining Tasks: {self.all_tasks.unfinished_tasks}")

                try:
                    task = self.tasks.get_nowait()
                    logger.debug(f"Execute Task ID: {task.name} - File: {task.properties['file_path']}")
                    task.run()
                except Empty:
                    #logger.debug("Tasks queue is empty...")
                    pass

    def new_task(self, func_handler, func_param=(), task_name="", task_type="", properties={}):
        task = _task(self, func_handler, func_param, task_name, properties, task_type)
        self.all_tasks.put_nowait(task)

    def stop(self):

        execute = True
        self.complete = True
        logger.info(f"Stopping {MONITOR_THREAD_NAME} ...")
        logger.debug("Waiting for all tasks to be finished...")
        while execute:
            if self.all_tasks.unfinished_tasks == 0 and self.tasks.unfinished_tasks == 0:
                """ Wai Max 10 seconds for MONITOR_THREAD_NAME to exit """
                index = 0
                running_threads = ""
                for thread in threading.enumerate():
                    running_threads += thread.name + " | "

                if MONITOR_THREAD_NAME in running_threads:
                    time.sleep(1)
                    index += 1

                    """ Exit the function if timeout has been reached """
                    if index == 10:
                        logger.warning(f"Daemon thread: {MONITOR_THREAD_NAME} remain started...")
                        execute = False

                else:
                    logger.info(f"{MONITOR_THREAD_NAME} - Exited successfully")
                    execute = False

    def wait_untill_processed(self, tasks_queue):

        execute = True
        while execute:
            running_threads = ''
            for thread in threading.enumerate():
                running_threads += thread.name + ' | '

            if 'TASK-' in running_threads:
                #print(running_threads)
                time.sleep(SYSTEM_TASK_SLEEP_TIME)
            else:
                logger.info('No more tasks running!')
                tasks_queue.mutex.acquire()
                tasks_queue.queue.clear()
                tasks_queue.all_tasks_done.notify_all()
                tasks_queue.unfinished_tasks = 0
                tasks_queue.mutex.release()
                self.complete = True
                execute = False


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

        if task_name:
            self.name = task_name
        else:
            self.name = "TASK-" + self.id

        if func_param:
            self.thread = threading.Thread(name=self.name, target=func_handler, args=func_param)
        else:
            self.thread = threading.Thread(name=self.name, target=func_handler)


    def get_output(self, output):
        self.result = output

    def run(self):
        try:
            self.thread.start()
            self.thread_id = self.thread.ident
        except Exception:
            logger.error(Exception)
            return None


