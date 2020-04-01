class Error(Exception):
    '''Base class for exceptions in this module.'''


class OrigSysError(Error):
    '''The given system cannot be replicated.'''


class OpSysError(OrigSysError):
    '''Unsupported operating system.'''
    def __init__(self, op_sys):
        self.op_sys = op_sys
        self.message = f"Unknown operating system {op_sys}. This likely means we haven't written "\
                       f"a SystemAnalyzer child class for this system yet."

class PermissionsError(OrigSysError):
    '''Insufficient permissions on target system.'''
    def __init__(self, user):
        self.user = user
        self.message = f"Insufficient permissions on the target system for {user}."
