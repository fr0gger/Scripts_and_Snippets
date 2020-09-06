#!/usr/bin/python
# Create a process in a suspended mode using CreateProcess API

import sys
from ctypes import *

WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p


# Specifies the window station, desktop, standard handles, and appearance 
# of the main window for a process at creation time.
class STARTUPINFO(Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPTSTR),
        ('lpDesktop', LPTSTR),
        ('lpTitle', LPTSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', WORD),
        ('cbReserved2', WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE),
    ]

# Contains information about a newly created process and its primary thread. 
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD),
    ]


def main():
    # Process to create
    exe = sys.argv[1]

    # Import the kernel32 lib
    kernel32 = windll.kernel32
	
    # creation flag
    CREATE_NEW_CONSOLE = 0x00000010
    CREATE_SUSPENDED = 0x00000004
    creation_flags = CREATE_NEW_CONSOLE | CREATE_SUSPENDED
	
    startupinfo = STARTUPINFO()
    processinfo = PROCESS_INFORMATION()
    startupinfo.cb = sizeof(startupinfo)

    try: 	
        kernel32.CreateProcessA(None, exe, None, None, None, creation_flags, None, None, byref(startupinfo), byref(processinfo))
        print("Process started as PID: {}".format(processinfo.dwProcessId))
        kernel32.CloseHandle(processinfo.hProcess)
        kernel32.CloseHandle(processinfo.hThread)
    except Exception as (e):
        print(e)
        kernel32.GetLastError()
		

if __name__ == '__main__':
    main()
