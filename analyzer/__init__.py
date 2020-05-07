'''
Runs when analyzer gets imported as a module. Handles various housekeeping items: checks Python
version, reads config, sets up logging, and manages relational importing.
'''

import sys
import configparser
import os

from logging.config import dictConfig



# Assert that we're running Python version >= 3.6.
if (sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 6)):
    raise Exception("Python 3.6 or a more recent version is required.")


from .utils import *


# Read in constants
CFG = configparser.ConfigParser()
CFG.read(os.path.join('defaults.ini'))
CFG.read(os.path.join('config.ini'))

LOG_LEVEL = CFG.get('GENERAL', 'LOG_LEVEL')
MACHINE_NAME = CFG.get('GENERAL', 'MACHINE_NAME')
HOSTNAME = CFG.get(MACHINE_NAME, 'HOSTNAME')
PORT = CFG.getint(MACHINE_NAME, 'PORT')
USERNAME = CFG.get(MACHINE_NAME, 'USERNAME')

HOST = Host(hostname=HOSTNAME, port=PORT, username=USERNAME)

# Configure logging
dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        },
        'minimal': {
            'format': '[%(filename)s:%(lineno)d] %(message)s',
        }
    },
    'handlers': {
        'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'formatter': 'default'
        },
        'filehandler': {
            'class': 'logging.FileHandler',
            'filename': 'pure_prototype_files.log',
            'mode': 'w',
            'level': 'DEBUG',
            'formatter': 'minimal'
        }
    },
    'loggers': {
        'filenames': {
            'propagate': False,
            'handlers': ['filehandler']
        }
    },
    'root': {
        'level': LOG_LEVEL,
        'handlers': ['wsgi']
    }
})


from .system import *

from .general import *
