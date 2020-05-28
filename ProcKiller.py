#Killing a Process using Windows API calls

import ctypes

u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("Kernel32.dll")
lpClassName=None
WindowName="Task Manager"
lpWindowName=ctypes.c_char_p(WindowName.encode('utf-8')) 


response = u_handle.FindWindowA(lpClassName,lpWindowName) #To find a handle to the window Of given Name
#Note:This handle is not the same as the handle in OpenProcess function.We are just grabbing reference to the process which does not require 
#any special privileges as in OpenProcess function.
error= k_handle.GetLastError()
if error != 0 :
    print("Error code is {0}".format(error))
    exit(1)

if response >=0 :
    print(response)
    hWnd = response
else:
    print("Could not grab a handle")

lpdwProcessId=ctypes.c_ulong() #Pointer to Process id

response=u_handle.GetWindowThreadProcessId(hWnd,ctypes.byref(lpdwProcessId)) #After the operation it will contain the Process id value
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
handle=k_handle.OpenProcess(dwDesiredAccess,bInheritHandle,lpdwProcessId) #Open process with that same process id obtained earlier
print(lpdwProcessId)
error2=k_handle.GetLastError()
if error2 != 0:
    print(error2)
if handle <= 0:
    print("handle not created")
else:
    print(handle)

response=k_handle.TerminateProcess(handle,1) #Terminate the process with exit code 1
