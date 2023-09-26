#include <windows.h>

#pragma comment(linker, "/EXPORT:DllMain")

extern "C" {
    #pragma comment(linker, "/EXPORT:1=library.dll.DllMain,@1")
    #pragma comment(linker, "/EXPORT:2=library.dll.myFunction1,@2")
    #pragma comment(linker, "/EXPORT:3=library.dll.myFunction2,@3")
}
