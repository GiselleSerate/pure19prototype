'''
Provides structures, custom errors, and global helper functions for the rest of the code.
'''

from typing import NamedTuple



class Host(NamedTuple):
    '''Use Host to keep info about a system'''
    hostname: str
    port: int
    username: str


class DockerDaemonError(Exception):
    '''Cannot reach the Docker daemon.'''


class OrigSysError(ValueError):
    '''The given system cannot be replicated.'''


class OrigSysConnError(OrigSysError):
    '''We can't connect to the system you want to replicate.'''


class OpSysError(OrigSysError):
    '''Unsupported operating system.'''


class PermissionsError(OrigSysError):
    '''Insufficient permissions on target system.'''
    # f"Insufficient permissions on the target system for {user}."


def group_strings(indexable, char_count=100000):
    '''
    Generator to group the indexable's items into space-separated strings which are about char_count
    characters long.
    '''
    curr_string = ""
    for item in indexable:
        if len(curr_string) > char_count:
            yield curr_string
            curr_string = ""
        curr_string += item + " "
    if curr_string:
        yield curr_string
