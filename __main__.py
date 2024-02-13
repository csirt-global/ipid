from sys import argv
from .ipid import identifyIP
if len(argv)>1:
    print(identifyIP(argv[1]))