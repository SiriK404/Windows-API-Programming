import ctypes

user_handle=ctypes.WinDLL("User32.dll")  #generates a handle to to User32.dll 
											#so we can use ctypes as proxy to reference 
                                            #whatever API calls we want
kernel_handle=ctypes.WinDLL("Kernel32.dll")  #For error handling


hWnd = None   #Parameters for MessageBoxW API call 
lpTest= "Hello Wrld"
lpCaption= "Hello"
uType= 0x00000001

response=user_handle.MessageBoxW(hWnd,lpTest,lpCaption,uType)     #Making the actual API call and 
                                                                   #Catching the response from that API call 

error=kernel_handle.GetLastError()              #Function to get the last error message

if error!=0 :
    print(error)
    exit(1)    #To let the OS know that something failed
    
if response == 1:
    print("User clicked OK")
    
elif response == 2:

    print("User Clicked Cancel")
    