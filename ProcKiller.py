import ctypes

u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("Kernel32.dll")
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

response=k_handle.TerminateProcess(handle,1)