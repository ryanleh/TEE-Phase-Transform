import logging
try:
    # noinspection PyUnresolvedReferences
    import win32con
    # noinspection PyUnresolvedReferences
    import win32security
    # noinspection PyUnresolvedReferences
    import aipythonlib
except:
    logging.error('error importing')
from contextlib import contextmanager

class ImpersonatorClass:
    def __init__(self, domain, login, password):
        self.Domain=domain
        self.Login=login
        self.Password=password
        self.LoggedIn = False

    @contextmanager
    def ExceptionHandler(self):
        try:
            yield
        except Exception, e:
            logging.exception(e)

    # noinspection PyUnreachableCode
    def Logon(self):
        if len(self.Login) == 0:
            logging.info("no login name provided")
            return True
        logging.info("logging in with name:{0}".format(self.Login))
        with self.ExceptionHandler():
            self.Handle=win32security.LogonUser(self.Login, self.Domain, self.Password, win32con.LOGON32_LOGON_INTERACTIVE, win32con.LOGON32_PROVIDER_DEFAULT)
            win32security.ImpersonateLoggedOnUser(self.Handle)
            self.LoggedIn = True
            return True
        return False

    def Logoff(self):
        if len(self.Login) == 0:
            return True
        if self.LoggedIn:
            with self.ExceptionHandler():
                win32security.RevertToSelf()
                self.Handle.Close()
                return True
        return False

    def __enter__(self):
        return self.Logon()

    def __exit__(self, exception_type, exception_val, trace):
        return self.Logoff()
