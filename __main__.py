from sys import argv
from .ipid import identify_ip
if len(argv)>1:
    print(identify_ip(argv[1]))