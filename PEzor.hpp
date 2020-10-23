#ifndef _HELLO_HPP_
#define _HELLO_HPP_

#include <windows.h>
#ifdef _DEBUG_
#include <iostream>
#endif

#include "inject.hpp"
#include "shellcode.hpp"
#include "sleep.hpp"

extern "C" {
    #include "loader.h"
}

#endif