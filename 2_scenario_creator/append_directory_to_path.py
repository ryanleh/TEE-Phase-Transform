"""
    This module is used to append directories to the path that python
    uses to search for modules
"""
import os
import sys

def append_to_path(*dirnames):
    """
        This function appends a directory, relative to the directory of the
        current file, to the PYTHONPATH.

        Example1: If function called from '/src/bin', then append_to_path('pkg', 'main')
            would append the path '/src/bin/pkg/main' to the PYTHONPATH.

        Example2: If function called from '/src/bin', then append_to_path('..')
            would append the path '/src' to the PYTHONPATH.

        @param *dirnames: A sequence of directory names(strings) with the
            first directory in the sequence being relative to the directory
            of the current file, and each one thereafter being relative to
            the previous directory in the sequence.
    """
    directory_of_this_file = os.path.dirname(__file__)
    path_to_directory = os.path.abspath(directory_of_this_file)
    join_relative_dir = os.path.join(path_to_directory, *dirnames)

    absolute_path = os.path.normpath(join_relative_dir)
    sys.path.append(absolute_path)