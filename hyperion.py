import logging
import sys
import argparse
from agents.core.taskmgr import task_manager

from agents.fileagent import *


app_name = "Hyperion"
""" Set working directory so the script can be executed from any location/symlink """
os.chdir(os.path.dirname(os.path.abspath(__file__)))

""" Logger settings """
logger = logging.getLogger('hyperion')
log_handler = logging.FileHandler('logs/hyperion.log')
log_file_format = logging.Formatter('%(levelname)s - THREAD-%(thread)d - %(asctime)s - %(filename)s - %(funcName)s - %(message)s')
log_handler.setFormatter(log_file_format)
logger.addHandler(log_handler)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)
log_console_format = logging.Formatter('%(message)s')
console_handler.setFormatter(log_console_format)
logger.addHandler(console_handler)
logger.setLevel(logging.NOTSET)  # Would be set by a parameter
logger_verobse_levels = ["INFO", "WARNING", "ERROR", "DEBUG"]

""" Hyperion settings """
samples_folder = 'samples/'

def check_args(args):

    """ Check and set appropriate logger level """

    args.verbose_level = args.verbose_level.upper()
    if args.verbose_level.upper() in logger_verobse_levels:
        if args.verbose_level == "INFO":
            logger.setLevel(logging.INFO)
        elif args.verbose_level == "WARNING":
            logger.setLevel(logging.WARNING)
        elif args.verbose_level == "ERROR":
            logger.setLevel(logging.ERROR)
        elif args.verbose_level == "DEBUG":
            logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)


def main(argv):

    argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                     description='Hyperion parser')

    """     -------------------------------------   Argument groups  ---------------------------------     """
    script_args = argsparser.add_argument_group('Script arguments', "\n")
    #query_args = argsparser.add_argument_group('Query arguments', "\n")

    """     -------------------------------------   Script arguments ---------------------------------     """
    script_args.add_argument("-v", "--verbose-level", type=str, action='store', dest='verbose_level', required=False,
                             default="WARNING", help="Set the verbose level to one of following: INFO, WARNING, ERROR or DEBUG (Default: WARNING)")

    args = argsparser.parse_args()
    argc = argv.__len__()

    """     -------------------------------------  Arguments check  ---------------------------------     """
    check_args(args)

    logger.info(f"Starting {app_name}")
    logger.info(f"Initiating Task Manager")
    taskmgr = task_manager()

    logger.info(f"Looking for samples in: {samples_folder}")

    if os.path.isfile(samples_folder):
        pass
    else:
        for file in os.listdir(samples_folder):
            file_path = samples_folder + r"/" + file
            if os.path.isfile(file_path):

                task = taskmgr.create_task(fileagent, (file_path,), "fileagent")
                task.run()
                #  _fagent = fileagent(file_path, "rtf")

if __name__ == "__main__":
    main(sys.argv)