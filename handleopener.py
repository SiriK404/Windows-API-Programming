import ctypes

k_handle=ctypes.WinDLL("Kernel32.dll")

PROCESS_ALL_ACCESS= ( 0x000F0000 | 0x00100000 | 0xfff)

dwDesiredAccess=PROCESS_ALL_ACCESS
bInheritHandle= False

ProcessId=int(input("Enter the process id of the process to create a handle to :"))

response=k_handle.OpenProcess(dwDesiredAccess,bInheritHandle,ProcessId)

error=k_handle.GetLastError()

if error !=0 :
    print("error code is : {0}".format(error))
    #exit(1)
    
if response <=0:
    print("handle not created")

else:
    print(response)