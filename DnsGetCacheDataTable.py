#Implementation of an undocumented API call DnsGetCacheDataTable()

import ctypes
from ctypes.wintypes import *

k_handle=ctypes.WinDLL("Kernel32.dll")
d_handle=ctypes.WinDLL("DNSAPI.dll")
#Description of parameters of the structure:
# pNext is a pointer to the next dns cache entry.We pass an initial an initial DNS cache

# entry.Once its passed it will chain them up.
# recName is hostname we were able to find
# wType is what type of DNS entry it is
# wDataLength is length of DNS entry


class DNS_CACHE_ENTRY(ctypes.Structure):
    _fields_=[("pNext",HANDLE),
              ("recName",LPWSTR),
              ("wType",DWORD),
              ("wDataLength",DWORD),
              ("dwFlags",DWORD)
              ]

DNS_Entry=DNS_CACHE_ENTRY()
DNS_CACHE_ENTRY.wDataLength= 1024

response=d_handle.DnsGetCacheDataTable(ctypes.byref(DNS_Entry))

if response ==0 :
    print("error code {0}".format(k_handle.GetLastError()))

#When we get a memory location from windows api call that contains a structure,we can cast the memory address and
#have python and ctypes rebuild the memory structure using the returned address as the starting point
#cast takes two parameters, a ctypes object that is or can be converted to a pointer of some kind, and a ctypes pointer type.
#It returns an instance of the second argument, which references the same memory block as the first argument

DNS_Entry=ctypes.cast(DNS_Entry.pNext,ctypes.POINTER(DNS_CACHE_ENTRY))

while True:
    try:
        print("DNS Entry {0} :Type {1}".format(DNS_Entry.contents.recName,DNS_Entry.contents.wType))
        DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(DNS_CACHE_ENTRY))

    except:
        break
