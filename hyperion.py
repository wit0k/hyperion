import sys
from agents.fileagent import *


""" Set working directory so the script can be executed from any location/symlink """
os.chdir(os.path.dirname(os.path.abspath(__file__)))

folder = 'samples/'

if os.path.isfile(folder):
    _fagent = fileagent(folder, "rtf")
else:
    test = os.listdir(folder)
    for file in os.listdir(folder):
        file_path = folder + r"/" + file
        if os.path.isfile(file_path):
            _fagent = fileagent(file_path, "rtf")