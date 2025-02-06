---
layout: post
title: Anti-Debug Technique with TLS Callback 
description: "Explore the use of TLS callbacks in Windows PE files as an anti-debugging technique."
date: 2025-01-27 
categories: malware
tags: malware Anti-Debug

author: default
---

## TLS Callbacks

TLS (Thread Local Storage) callbacks are a mechanism in Windows that are stored in the PE header(IMAGE_DIRECTORY_ENTRY_TLS) and allows a program to define a function that will be called when the process starts, terminates, a thread is created or terminated.
These callbacks can be used to perform various tasks, such as initializing thread-specific data or modifying the behavior of the thread.

They are invoked just before the Original Entry Point (OEP) of the program makeing them suitable for anti-debugging technique.    


## Anti-dbg TLS Callback Example

```c++
#include <windows.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "ntdll.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
// Force the inclusion of the TLS directory.
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#define readPEB ((PBOOLEAN)((PBYTE)__readgsqword(0x60) + 2))
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#define readPEB ((PBOOLEAN)((PBYTE)__readfsdword(0x30) + 2))
#endif


// Declaration of NtQueryInformationProcess from ntdll.dll.
extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE hProcess,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// For output without CRT dependencies.
void SafePrint(const char* msg) {
    DWORD bytesWritten;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(hStdOut, msg, (DWORD)strlen(msg), &bytesWritten, NULL);
}

// TLS callback function.
void NTAPI DebuggerDetect(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason != DLL_PROCESS_ATTACH)
        return;


    // Check the PEB for the BeingDebugged flag.
    PBOOLEAN BeingDebugged = readPEB;
    if (BeingDebugged && *BeingDebugged) {
        SafePrint("Debugger Detected via PEB!\n");
        Sleep(2000);
        TerminateProcess(GetCurrentProcess(), 1);
    }

    // Check via NtQueryInformationProcess (ProcessDebugPort, InfoClass 7).
    HANDLE DebugPort = NULL;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(), 7, &DebugPort, sizeof(HANDLE), NULL
    );
    if (NT_SUCCESS(status) && DebugPort) {
        SafePrint("Debugger Detected via NtQuery!\n");
        Sleep(2000);
        TerminateProcess(GetCurrentProcess(), 1);
    }
}

// Place the array in a known TLS section (commonly ".CRT$XLC").

#ifdef _WIN64
#pragma const_seg(".CRT$XLC")
EXTERN_C const PIMAGE_TLS_CALLBACK pTlsCallbacks[] = { DebuggerDetect, 0 };
#pragma const_seg()
#else
#pragma data_seg(".CRT$XLC")
EXTERN_C PIMAGE_TLS_CALLBACK pTlsCallbacks[] = { DebuggerDetect, 0 };
#pragma data_seg()
#endif

int main() {
    printf("Entrypoint Executed!\n");
    return 0;
}
```


 