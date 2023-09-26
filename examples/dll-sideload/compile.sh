x86_64-w64-mingw32-gcc -shared -static library.c -o library.dll library.def -Wall -pedantic -Wextra &&
x86_64-w64-mingw32-g++ -static main.cpp -o main.exe
