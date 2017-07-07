import traceback
import sys
import os
import importlib
import re

"""
Phase object should have filename, class name, imports, required param, and optional
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
        self.req_params, self.opt_params = self._getParams()
        self.class_name = self._getClassname()



    def _getImports(self):
        """
        Returns all imports

        >>> PhaseParams("tcp_connect.py", '/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter'\
                '.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect.py')._getImports()
        ['ai_utils.phases.abstract_phase', 'socket']


        >>> PhaseParams("crack_hash.py", '/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter'\
                '.scenario_dir_name }}/bin/ai_utils/phases/crack_hash.py')._getImports()
        ['ai_utils.phases.abstract_phase', 'logging', 'Hash_Cracker']

        >>> PhaseParams("tcp_connec.py", '/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter'\
                '.scenario_dir_name }}/bin/ai_utils/phases/tcp_connec.py')._getImports() #doctest: +ELLIPSIS
        Traceback (most recent call last):
         ...
        IOError: [Errno 2] No such file or directory:...
        """
        imports = []

        file = open(self.path)
        for line in file:
            line = line.lstrip()
            if line[:6] == "import":
                imports.append(line.split(" ")[1].rstrip("\n"))
            elif line[:4] == "from":
                imports.append(line.split(" ")[1].rstrip("\n"))

        file.close()

        return imports

    def _filterImports(self):
        """
        Removes any imports in Python stdlib or ai_utils

        >>> PhaseParams("tcp_connect.py", '/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter'\
                '.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect.py')._filterImports()
        []
        >>> PhaseParams("crack_hash.py", '/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter'\
                '.scenario_dir_name }}/bin/ai_utils/phases/crack_hash.py')._filterImports()
        ['Hash_Cracker']

        """
        imports = self._getImports()

        # Find a more elegant solution pls
        i = len(imports) - 1
        tmp_path = sys.path
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
        sys.path = tmp_path

        return imports


    def _getParams(self):
        """
        Grabs and sorts phase arguments

        >>> PhaseParams("tcp_connect.py", '/home/ryan/projects/scenario_creator/cookiecutter-scenario/{{ cookiecutter'\
                '.scenario_dir_name }}/bin/ai_utils/phases/tcp_connect.py')._getParams()
        (['ip', 'port'], ['message'])

        """
        req_params = []
        opt_params = []

        # Pretty rudimentary implementation... TODO: more elegant solution

        file = open(self.path)
        for line in file:
            line = line.lstrip()
            if line[:13] == "def __init__(":
                arg_list = re.search('def __init__\((.+?)\):', line).group(1).split(",")[2:]
                for arg in arg_list:
                    if "=" not in arg:
                        req_params.append(arg.lstrip())
                    else:
                        opt_params.append(arg.lstrip().split("=")[0].rstrip(" "))

        return req_params, opt_params

    def _getClassname(self):
        """
        Grabs phase class name
        """

        # TODO: more elegant solution


        file = open(self.path)
        for line in file:
            line = line.lstrip()
            if line[:5] == "class":
                return re.search('class (.+?)\(', line).group(1)





