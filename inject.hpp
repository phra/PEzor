#ifndef _INJECT_HPP_
#define _INJECT_HPP_

#include <windows.h>
#ifdef _DEBUG_
#include <iostream>
#endif
#include <unistd.h>
#include <synchapi.h>
#include "syscalls.hpp"

void my_init_syscalls_list(void);
LPVOID inject_shellcode_self(unsigned char shellcode[], SIZE_T size, PHANDLE phThread, BOOL wait, unsigned int sleep_time);

#endif
