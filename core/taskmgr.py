import threading
import logging
import os
from queue import Queue, Empty
logger = logging.getLogger('hyperion')
import time
import datetime
import hashlib

logger = logging.getLogger('hyperion')
MONITOR_THREAD_NAME = "TaskMgr.Tasks.Handler"
MAX_SIMULTANEOUS_TASKS_COUNT = 5
SYSTEM_TASK_SLEEP_TIME = 100/1000.0

class task_manager(object):


    tasks = Queue(maxsize=MAX_SIMULTANEOUS_TASKS_COUNT)
    all_tasks = Queue()
    results = Queue()

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

            # Case where there are no remaining tasks and there are only executed/unfinished tasks
            elif self.tasks.unfinished_tasks > 0 and self.all_tasks.unfinished_tasks == 0 and self.tasks.qsize() == 0:
                time.sleep(SYSTEM_TASK_SLEEP_TIME)
            else:
                """ Execute the tasks """
                try:
                    task = self.tasks.get_nowait()
                    logger.debug(f"Execute Task ID: {task.name} - File: {task.file}")
                    task.run()
                except Empty:
                    #logger.debug("Tasks queue is empty...")
                    pass

    def new_task(self, file, file_type, handler, func_handler, func_param=(), task_name="", task_type="", scanner=None):
        task = _task(self, file, file_type, handler, func_handler, func_param, task_name, scanner, task_type)
        self.all_tasks.put_nowait(task)

    def stop(self):
        """ Stops the Task Manager gracefully """
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
        """ Manual implementation of .join on the task_queue """

        logger.debug(f"Waiting for Task threads to finish ...")
        time.sleep(MAX_SIMULTANEOUS_TASKS_COUNT)

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

    def print_results(self):
        execute = True
        while execute:
            try:
                print(self.results.get_nowait())
                self.results.task_done()
            except Exception:
                execute = False
                logger.debug("End printing. Nothing in the queue ...")

    # Helper function, will be soon moved to Core
    def _md5(self, fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

class _task():

    def __init__(self, taskmgr, file, file_type, handler, func_handler, func_param=(), task_name="", scanner={}, task_type=""):

        self.file = file
        self.file_path = os.path.basename(self.file)
        self.file_type = file_type
        self.taskmgr = taskmgr
        self.file_hash = self.taskmgr._md5(self.file)
        self.type = task_type
        self.name = task_name
        self.id = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S-') + self.file_hash.upper()
        self.scanner = scanner
        """ Set appropriate task name """
        if task_name:
            # System task
            self.name = task_name
        else:
            # Handler task
            self.name = "TASK-" + self.id

        self.thread = None
        self.thread_id = None
        self.handler = handler  # Allows further manipulation of handler's properties (if needed)
        self.function_handler = None  # Custom function handler (usually .run method of the handler)

        self.ioc = {}

        """ Fill-in task specific properties by task type """
        if self.type == "file":
            pass

        """ Build a new thread accordingly to function parameter (task object is always sent)"""
        if func_param:
            self.thread = threading.Thread(name=self.name, target=func_handler, args=(self, ) + func_param)
        else:
            self.thread = threading.Thread(name=self.name, target=func_handler, args=(self, ))

    def run(self):
        try:
            self.thread.start()
            # Thread ID is available only after starting it
            self.thread_id = self.thread.ident
        except Exception:
            logger.error(Exception)
            return None

    def task_done(self, task_result):
        try:
            logger.debug(f"Close Task: {self.file} -> Queue unfinished_tasks: {self.taskmgr.tasks.unfinished_tasks}")
            if task_result:

                """ Convert to result object """
                _result = result(self.thread_id, self.id, self.name, self.type, task_result)

                self.taskmgr.results.put(task_result)
            self.taskmgr.tasks.task_done()
        except ValueError:
            pass


class result(object):

    def __init__(self, thread_id, task_id, task_name, task_type, task_data):

        self.type = None

        if task_type:
            if task_type == "file":
                self.type = task_type
                self.info = file_info(thread_id, task_id, task_name)
                self.data = _data(task_data)
                self.ioc = file_ioc(task_data)

        test = ""

class file_info(object):

    def __init__(self, thread_id, task_id, task_name):
        self.task_name = task_name
        self.task_id = task_id
        self.thread_id = thread_id
        self.meta_data = None

class _data():

    def __init__(self, task_data):
        self.items = task_data


class file_ioc():
    def __init__(self, data):

        self.ip = []
        self.url = []
        self.email = []
        self.domain = []
        self.exe_name = []
        self.btc = []
        self.file_path = []

