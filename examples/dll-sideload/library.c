#include <windows.h>
#include <stdio.h>

__declspec(dllexport) int myFunction1() {
    return 1;
}

__declspec(dllexport) int myFunction2() {
    return 2;
}

int myAnonymousFunction() {
  return 3;
}

__declspec(dllexport) int DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    puts("libray.dll DLLMain\n");
    return 1;
}

