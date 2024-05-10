#! /usr/bin/env python3
import glob
import pefile
import sqlite3 # use sqlite_web?

recursive = True
folders = [
    "C:\\Windows\\System32\\",
    "C:\\Program **\\Windows Defender**\\"
]

extensions = [
    "exe",
    "dll"
]

dlls = []

for folder in folders:
    for extension in extensions:
        dlls += glob.glob(f"{folder}**\\*.{extension}", recursive=recursive)

def get_func_name(func):
    if func.name:
        return func.name.decode("utf8")
    else:
        return f"#{func.ordinal}"

def parse_pe_file(path: str):
    pe = pefile.PE(path)

    basename = path[path.rindex("\\") + 1:].lower()
    imports = []
    exports = []

    if "DIRECTORY_ENTRY_IMPORT" in dir(pe):
        for desc in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = desc.dll.decode("utf8").lower()
            imports += [(dll_name, get_func_name(func)) for func in desc.imports]

    if "DIRECTORY_ENTRY_EXPORT" in dir(pe):
        export_name = pe.DIRECTORY_ENTRY_EXPORT.name.decode("utf8")

        exports = [(export_name, get_func_name(func)) for func in pe.DIRECTORY_ENTRY_EXPORT.symbols]

    return {
        "name": basename,
        "path": path.lower(),
        "imports": imports,
        "exports": exports
    }

dll_info = [parse_pe_file(path) for path in dlls]

# Just write it out to CSV file for now
with open("imports.csv", "w") as f:
    f.write("dll, import_dll, name\n")
    for dll in dll_info:
        name = dll["name"]
        for (imp_dll, imp_function) in dll["imports"]:
            f.write(f"{name}, {imp_dll}, {imp_function}\n")

with open("exports.csv", "w") as f:
    f.write("export, name\n")
    for dll in dll_info:
        name = dll["name"]
        for (imp_dll, imp_function) in dll["exports"]:
            f.write(f"{imp_dll}, {imp_function}\n")
