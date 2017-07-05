import traceback
import sys
import os
import importlib

"""
Phase object should have filename, classname, imports, required param, and optional
params as variables
"""


class PhaseParams(object):
    def __init__(self, phase_name, phase_path):
        """
        Check if given phase exists
        """

        self.name = phase_name
        self.path = phase_path

        self.imports = self._filterImports()
        self.req_params = self._getRequiredParams()
        self.opt_params = self._getOptionalParams()


    def _getImports(self):
        """
        Returns all imports

        >>> PhaseParams._getImports(PhaseParams("tcp_connect.py","/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect.py"))
        ['ai_utils.phases.abstract_phase', 'socket']

        >>> PhaseParams._getImports(PhaseParams("crack_hash.py","/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases/crack_hash.py"))
        ['ai_utils.phases.abstract_phase', 'logging', 'Hash_Cracker']

        >>> PhaseParams._getImports(PhaseParams("tcp_connect", "/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect"))
        Traceback (most recent call last):
         ...
        IOError: [Errno 2] No such file or directory: '/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect'
        """
        imports = []

        file = open(self.path)
        for line in file:
            line = line.lstrip()
            if line[:6] == "import":
                imports.append(line.split(" ")[1].rstrip("\n"))
            elif line[:4] == "from":
                imports.append(line.split(" ")[1].rstrip("\n"))

        return imports

    def _filterImports(self):
        """
        Removes any imports in Python stdlib or ai_utils

        >>> PhaseParams._filterImports(PhaseParams("tcp_connect.py","/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect.py"))
        []
        >>> PhaseParams._filterImports(PhaseParams("crack_hash","/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases/crack_hash.py"))
        ['Hash_Cracker']

        """
        imports = self._getImports()

        # Find a more elegant solution pls
        i = len(imports) - 1
        lib_path = os.path.dirname(traceback.__file__)
        sys.path = [lib_path]
        while(i >= 0):
            if imports[i].split(".")[0] == "ai_utils":
                del imports[i]
                i -= 1
                continue
            try:
                importlib.import_module(imports[i], package=None)
                del imports[i]
            except ImportError:
                pass
            i -= 1


        return imports


    def _getRequiredParams(self):
        """
        Returns mandatory Params requested by __init__ of phase

        >>> PhaseParams._getRequiredParams(PhaseParams("tcp_connect.py","/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect.py"))
        ['ip', 'port']
        """
        req_params = []

        return req_params

    def _getOptionalParams(self):
        """
        Returns mandatory Params requested by __init__ of phase

        >>> PhaseParams._getOptionalParams(PhaseParams("tcp_connect.py","/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect.py"))
        ['message']
        """
        opt_params = []

        return opt_params




