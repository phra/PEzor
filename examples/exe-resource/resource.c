#include <windows.h>
#include "resource.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Load the message and title from the resource
    wchar_t message[256], title[256];
    
    LoadStringW(hInstance, IDS_MESSAGE, message, sizeof(message) / sizeof(wchar_t));
    LoadStringW(hInstance, IDS_TITLE, title, sizeof(title) / sizeof(wchar_t));

    // Display the MessageBox
    MessageBoxW(NULL, message, title, MB_OK | MB_ICONINFORMATION);

    return 0;
}
