'''
Provides data structures for the rest of the code.
'''

from typing import NamedTuple



class Host(NamedTuple):
    '''Use Host to keep info about a system'''
    hostname: str
    port: int
    username: str
