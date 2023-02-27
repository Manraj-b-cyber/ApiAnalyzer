import pefile

def check_for_process_injection(iat):
    # Set of API calls used in process injection
    process_injection_apis = {
        "CreateRemoteThread",
        "VirtualProtect",
        "WriteProcessMemory",
        "OpenProcess"
    }

    found_apis = []
    # Iterate over the IAT entries and check for the presence of process injection API calls
    for entry in iat:
        for imp in entry.imports:
            if imp.name.decode("utf-8") in process_injection_apis:
                found_apis.append(imp.name.decode("utf-8"))

    return found_apis

def check_for_Create_Process_apis(iat):
    # Set of API calls used in Creating a Process
    Create_process_apis = {
        "CreateProcessA"
    }

    found_apis = []
    # Iterate over the IAT entries and check for the presence of urldownload API calls
    for entry in iat:
        for imp in entry.imports:
            if imp.name.decode("utf-8") in Create_process_apis:
                found_apis.append(imp.name.decode("utf-8"))

    return found_apis
    
def check_for_Process_Hollowing(iat):
    # Set of API calls used in Process Hollowing
    Process_Hollowing_Api = {
        "NTqueryinformationprocess",
        "CreateProcessA",
        "VirtualAlloc",
        "VirtualAllocEx",
        "ReadProcessMemory",
        "FindResourceA",
        "NTUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "WriteProcessMemory",
        "VirtualProtectEx",
        "SetThreadContext",
        "NtResumeThread"
    }

    found_apis = []
    # Iterate over the IAT entries and check for the presence of Process_Hollowing API calls
    for entry in iat:
        for imp in entry.imports:
            if imp.name.decode("utf-8") in Process_Hollowing_Api:
                found_apis.append(imp.name.decode("utf-8"))

    return found_apis


def check_for_Keylogging(iat):
    # Set of API calls used in KeyLogging
    KeyLogging_Api = {
        "SetWindowHookExA",
        "LowLevelKeyboardProc",
        "CallNextHookEx",
        "GetAsyncKeyState",
        "SetWindowsHookExA"
        }

    found_apis = []
    # Iterate over the IAT entries and check for the presence of Key Logging API calls
    for entry in iat:
        for imp in entry.imports:
            if imp.name.decode("utf-8") in KeyLogging_Api:
                found_apis.append(imp.name.decode("utf-8"))

    return found_apis

def check_for_Process_Enumeration(iat):
    # Set of API calls used in Process Enumeration and snapshotting
    ProcessEnum_Api = {
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32NextW",
        "OpenProcess"
        }

    found_apis = []
    # Iterate over the IAT entries and check for the presence of Process Enumeration
    for entry in iat:
        for imp in entry.imports:
            if imp.name.decode("utf-8") in ProcessEnum_Api:
                found_apis.append(imp.name.decode("utf-8"))

    return found_apis

# Open the binary file
pe = pefile.PE("/home/manny/Documents/mal-dev/test/procinj.exe")

# Get the IAT
iat = pe.DIRECTORY_ENTRY_IMPORT

# Iterate over the IAT entries and print the API calls
for entry in iat:
    print(entry.dll)
    for imp in entry.imports:
        print("\t", imp.name)

# Check for the presence of process injection API calls
found_process_injection_apis = check_for_process_injection(iat)
if found_process_injection_apis:
    print("Process injection API calls found in binary: ", found_process_injection_apis)
else:
    print("No process injection API calls found in binary")

# Check for the presence of Create Process API calls
found_Create_process_apis = check_for_Create_Process_apis(iat)
if found_Create_process_apis:
    print("Create Process API calls found in binary: ", found_Create_process_apis)
else:
    print("No Create Process API calls found in binary")
    
# Check for the presence of Process Hollowing API calls
found_check_for_Process_Hollowing = check_for_Process_Hollowing(iat)
if found_check_for_Process_Hollowing:
    print("Process Hollowing API calls found in binary: ", found_check_for_Process_Hollowing)
else:
    print("No Process Hollowing API calls found in binary")
    
# Check for the presence of KeyLogging API calls
found_check_for_KeyLogging = check_for_Keylogging(iat)
if found_check_for_KeyLogging:
    print("KeyLogging API calls found in binary: ", found_check_for_KeyLogging)
else:
    print("No KeyLogging API calls found in binary")
    
# Check for the presence of Process Enumeration API calls
found_check_for_ProcessEnum = check_for_Process_Enumeration(iat)
if found_check_for_ProcessEnum:
    print("Process Enumeration API calls found in binary: ", found_check_for_ProcessEnum)
else:
    print("No Process Enumeration API calls found in binary") 
    
