#include <windows.h>
#include <iostream>

int main() {
    HMODULE hModule = LoadLibraryW(L"library.dll"); // Load the DLL
    if (hModule != NULL) {
        int (*getVariable1)() = (int(*)())GetProcAddress(hModule, (LPCSTR)2); // Access ordinal 1
        int (*getVariable2)() = (int(*)())GetProcAddress(hModule, (LPCSTR)3); // Access ordinal 2

        if (getVariable1 != NULL && getVariable2 != NULL) {
            int value1 = getVariable1();
            int value2 = getVariable2();
            
            // Use 'value1' and 'value2' here
            std::cout << "Value 1: " << value1 << std::endl;
            std::cout << "Value 2: " << value2 << std::endl;
        }

	Sleep(10000);

        FreeLibrary(hModule); // Unload the DLL when done
    } else {
        std::cout << "DLL NOT FOUND" << std::endl;
    }
    return 0;
}

