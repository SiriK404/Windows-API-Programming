#This program opens a privileged handle to access token of the process
import ctypes
from ctypes.wintypes import *

u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("Kernel32.dll")
a_handle=ctypes.WinDLL("Advapi32.dll")
lpClassName=None
WindowName="Task Manager"
lpWindowName=ctypes.c_char_p(WindowName.encode('utf-8'))


response = u_handle.FindWindowA(lpClassName,lpWindowName)
error= k_handle.GetLastError()
if error != 0 :
    print("Error code is {0}".format(error))
    exit(1)

if response >=0 :
    print(response)
    hWnd = response
else:
    print("Could not grab a handle")

lpdwProcessId=ctypes.c_ulong()

response=u_handle.GetWindowThreadProcessId(hWnd,ctypes.byref(lpdwProcessId))
error1=k_handle.GetLastError()
if error1 != 0:
    print("error code is {0}".format(error1))

if response >=0:
    print(response)
else:
    print("Could not grab process Id")

PROCESS_ALL_ACCESS= ( 0x000F0000 | 0x00100000 | 0xfff)
# Token Access Rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
					TOKEN_ASSIGN_PRIMARY     |
					TOKEN_DUPLICATE          |
					TOKEN_IMPERSONATION      |
					TOKEN_QUERY              |
					TOKEN_QUERY_SOURCE       |
					TOKEN_ADJUST_PRIVILEGES  |
					TOKEN_ADJUST_GROUPS      |
					TOKEN_ADJUST_DEFAULT     |
					TOKEN_ADJUST_SESSIONID)

dwDesiredAccess=PROCESS_ALL_ACCESS
bInheritHandle= False
handle=k_handle.OpenProcess(dwDesiredAccess,bInheritHandle,lpdwProcessId)
print(lpdwProcessId)
error2=k_handle.GetLastError()
if error2 != 0:
    print(error2)
if handle <= 0:
    print("handle not created")
else:
    print(handle)

ProcessHandle=handle
DesiredAccess=TOKEN_ALL_ACCESS
TokenHandle=ctypes.c_void_p()

response=a_handle.OpenProcessToken(ProcessHandle,DesiredAccess,ctypes.pointer(TokenHandle))

if response ==0:
    print("error code {0}".format(k_handle.GetLastError()))
else:
    print(response)
