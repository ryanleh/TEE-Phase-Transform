import os

"""
Sets global directory and stdarg variables
"""



class GlobalParams(object):
    def __init__(self):
        self.builder_root = ""
        self.phase_dir = ""
        self.template_dir = ""
        self.library_dir = ""
        self.setDir()

    def setDir(self):
        """
        Set directory variables

        >>> GlobalParams().builder_root
        '/home/ryan/projects/scenario_creator'
        >>> GlobalParams().phase_dir
        '/home/ryan/projects/scenario_creator/bin/ai_utils/phases'
        >>> GlobalParams().template_dir
        '/home/ryan/projects/scenario_creator/cookiecutter-scenario'
        >>> GlobalParams().library_dir
        '/home/ryan/projects/scenario_creator/bin'
        """


        self.builder_root = os.path.dirname(os.path.realpath(__file__))

        self.phase_dir = os.path.join(self.builder_root,"bin/ai_utils/phases")
        self.template_dir = os.path.join(self.builder_root,"cookiecutter-scenario")
        self.library_dir = os.path.join(self.builder_root,"bin")


    def setStdArgList(self):
        """
        Idk how you want to populate this but grab some sort of global dictionary list
        with parameters... this might have to just be static.  You might need
        to have an argument class within a dictionary?  Populate from JSON object?
        """
