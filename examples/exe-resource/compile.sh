x86_64-w64-mingw32-windres resource.rc -o resource.o &&
x86_64-w64-mingw32-gcc resource.c resource.o -o MessageBoxExample.exe -mwindows
