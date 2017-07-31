import logging

class AbstractCodeInjectionAgentClass(object):
    def __init__(self):
        logging.info('Executing AbstractCodeInjectionAgentClass...')

    def InjectCode(self):
        """override to inject code into a process"""
        return True
