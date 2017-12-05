import logging
from agents.fileagent import *


""" Set working directory so the script can be executed from any location/symlink """
os.chdir(os.path.dirname(os.path.abspath(__file__)))

""" Logger settings """
logger = logging.getLogger('hyperion')
log_handler = logging.FileHandler('logs/hyperion.log')
log_handler.setLevel(logging.DEBUG)
log_file_format = logging.Formatter('%(levelname)s - %(asctime)s - %(filename)s - %(funcName)s - %(message)s')
log_handler.setFormatter(log_file_format)
logger.addHandler(log_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)
log_console_format = logging.Formatter('%(message)s')
console_handler.setFormatter(log_console_format)
logger.addHandler(console_handler)

""" Hyperion settings """
samples_folder = 'samples/'

logger.error(f"Looking for sample in: {samples_folder}")

if os.path.isfile(samples_folder):
    _fagent = fileagent(samples_folder, "rtf")
else:
    test = os.listdir(samples_folder)
    for file in os.listdir(samples_folder):
        file_path = samples_folder + r"/" + file
        if os.path.isfile(file_path):
            _fagent = fileagent(file_path, "rtf")