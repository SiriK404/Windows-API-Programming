import ctypes
from ctypes.wintypes import *

k_handle=ctypes.WinDLL("Kernel32.dll")

class STRATUPINFO(ctypes.Structure): #Structure For Startupinfo
    _fields_=[("cb",DWORD),
              ("lpReserved",LPSTR),
              ("lpDesktop",LPSTR),
              ("lpTitle",LPSTR),
              ("dwX",DWORD),
              ("dwY",DWORD),
              ("dwXSize",DWORD),
              ("dwYSize",DWORD),
              ("dwXCountChars",DWORD),
              ("dwYCountChars",DWORD),
              ("dwFillAttribute",DWORD),
              ("dwFlags",DWORD),
              ("wShowWindow",WORD),
              ("cbReserved2",WORD),
              ("lpReserved2",LPBYTE),
              ("hStdInput",HANDLE),
              ("hStdOutput",HANDLE),
              ("hStdError",HANDLE)
             ]

class PROCESS_INFORMATION(ctypes.Structure): #Structure for Process Info
    _fields_=[("hProcess",HANDLE),
              ("hThread",HANDLE),
              ("dwProcessId",DWORD),
              ("dwThreadId",DWORD)
              ]

lpApplicationName="C:\Windows\System32\cmd.exe"
lpCommandLine= None
lpProcessAttributes=None
lpThreadAttributes=None
bInheritHandles=False
dwCreationFlags=0x00000010
lpEnvironment=None
lpCurrentDirectory=None
lpStartupInfo=STRATUPINFO()  #These are pointers So we reference them using empty structures.The values get
                            #populated when they are called by reference
lpProcessInformation=PROCESS_INFORMATION()

lpStartupInfo.dwFlags=0x00000001
lpStartupInfo.wShowWindow=0x1

response=k_handle.CreateProcessW(lpApplicationName,
                                 lpCommandLine,
                                 lpProcessAttributes,
                                 lpThreadAttributes,
                                 bInheritHandles,
                                 dwCreationFlags,
                                 lpEnvironment,
                                 lpCurrentDirectory,
                                 ctypes.byref(lpStartupInfo),
                                 ctypes.byref(lpProcessInformation)
                                 )
                                        #Use By Reference whenever a pointer is called
if response > 0 :
    print("Process is created")
    print(lpProcessInformation.dwProcessId,lpStartupInfo)
else:
    print("error code is {0}".format(k_handle.GetLastError()))




