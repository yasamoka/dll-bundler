import os
import sys
from pathlib import Path
from shutil import copyfile

from pefile import PE
from dlldiag.common import WindowsApi, ModuleHeader


def bundle(dll_filepaths, dependency_search_paths, package_dir):
    try:
        os.mkdir(package_dir)
    except OSError:
        pass

    for dll_filepath in dll_filepaths:
        dll_copy = Path(package_dir, Path(dll_filepath).name)
        copyfile(dll_filepath, dll_copy)

    search_path_dll_map = {}
    for search_path in reversed(dependency_search_paths):
        search_path = Path(search_path)
        dll_paths = [path for path in search_path.iterdir() if path.suffix == ".dll"]
        for dll_path in dll_paths:
            search_path_dll_map[dll_path.name] = search_path
    
    extra_dependencies = {}
    for dll_filepath in dll_filepaths:
        _locate_extra_dependencies(dll_filepath, search_path_dll_map, extra_dependencies, package_dir)
    extra_dependencies_list = extra_dependencies.values()
    return extra_dependencies_list

def _locate_extra_dependencies(dll_filepath, search_path_dll_map, extra_dependencies, package_dir):
    dll_filepath = Path(dll_filepath)
    
    header = ModuleHeader(dll_filepath)
    architecture = header.getArchitecture()

    pe = PE(dll_filepath)
    pe.parse_data_directories(import_dllnames_only=True)

    if dll_filepath.name in extra_dependencies:
        return
    
    extra_dependencies[dll_filepath.name] = dll_filepath
    for dependency in pe.DIRECTORY_ENTRY_IMPORT:
        dependency_dll_name = dependency.dll.decode('utf-8')
        try:
            result = WindowsApi.loadModule(dependency_dll_name, cwd=dll_filepath.parent, architecture=architecture)
            assert result in (0, 126)
        except AssertionError:
            print(f"Encountered error {result} for dependency {dependency_dll_name}. Aborting ...")
            exit(1)
        
        if result == 126:
            try:
                search_path = search_path_dll_map[dependency_dll_name]
                if dependency_dll_name not in extra_dependencies:
                    dependency_dll_filepath = Path(search_path, dependency_dll_name)
                    dependency_dll_copy_filepath = Path(package_dir, dependency_dll_filepath.name)
                    copyfile(dependency_dll_filepath, dependency_dll_copy_filepath)
                    _locate_extra_dependencies(dependency_dll_copy_filepath, search_path_dll_map, extra_dependencies, package_dir)
            except KeyError:
                print(f"Dependency {dependency_dll_name} was not found in any search path. Aborting ...")
                exit(1)
