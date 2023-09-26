#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    puts("ForwardedDLL DllMain");
    return TRUE;
}
