import sys


# Assert that we're running Python version >= 3.6.
if (sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 6)):
    raise Exception("Python 3.6 or a more recent version is required.")


from logging.config import dictConfig

from .utils import *


# Constants (which we can move into a config file later)
LOG_LEVEL = 'INFO'

# Centos
HOST = Host(hostname='127.0.0.1', port=2222, username='root')

# Ubuntu
# HOST = structs.Host(hostname='127.0.0.1', port=3333, username='root')

# Ubuntu container
# HOST = structs.Host(hostname='127.0.0.1', port=1022, username='sshuser')

# Centos container
# HOST = structs.Host(hostname='127.0.0.1', port=1222, username='sshuser')


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
