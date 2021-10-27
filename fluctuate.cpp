#include "fluctuate.hpp"

unsigned char originalBytes[16] = { 0 };
unsigned int originalProtection = 0;
unsigned int XOR_KEY = 0;

#ifdef _DEBUG_
// https://gist.github.com/ccbrown/9722406
void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		wprintf(L"%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			wprintf(L" ");
			if ((i+1) % 16 == 0) {
				wprintf(L"|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					wprintf(L" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					wprintf(L"   ");
				}
				wprintf(L"|  %s \n", ascii);
			}
		}
	}
}

void print_protection(void* address, DWORD protections) {
    if (protections & PAGE_READONLY)
        wprintf(L"print_protection: 0x%p is PAGE_READONLY\n", address);
    if (protections & PAGE_READWRITE)
        wprintf(L"print_protection: 0x%p is PAGE_READWRITE\n", address);
    if (protections & PAGE_NOACCESS)
        wprintf(L"print_protection: 0x%p is PAGE_NOACCESS\n", address);
    if (protections & PAGE_WRITECOPY)
        wprintf(L"print_protection: 0x%p is PAGE_WRITECOPY\n", address);
    if (protections & PAGE_EXECUTE)
        wprintf(L"print_protection: 0x%p is PAGE_EXECUTE\n", address);
    if (protections & PAGE_EXECUTE_READ)
        wprintf(L"print_protection: 0x%p is PAGE_EXECUTE_READ\n", address);
    if (protections & PAGE_EXECUTE_READWRITE)
        wprintf(L"print_protection: 0x%p is PAGE_EXECUTE_READWRITE\n", address);
    if (protections & PAGE_EXECUTE_WRITECOPY)
        wprintf(L"print_protection: 0x%p is PAGE_EXECUTE_WRITECOPY\n", address);
    if (protections & PAGE_GUARD)
        wprintf(L"print_protection: 0x%p is PAGE_GUARD\n", address);
    if (protections & PAGE_NOCACHE)
        wprintf(L"print_protection: 0x%p is PAGE_NOCACHE\n", address);
}

void print_type(void* address, DWORD type) {
    if (type & MEM_IMAGE)
        wprintf(L"print_type: 0x%p is MEM_IMAGE\n", address);
    if (type & MEM_MAPPED)
        wprintf(L"print_type: 0x%p is MEM_MAPPED\n", address);
    if (type & MEM_PRIVATE)
        wprintf(L"print_type: 0x%p is MEM_PRIVATE\n", address);
}
#endif

unsigned int generate_random_int() {
    std::srand(std::time(nullptr));
    return std::rand() | std::rand() << 16;
}

void xor32(void* address, unsigned int size, unsigned int key) {
    #ifdef _DEBUG_
        wprintf(L"xor32: before xor 0x%p:\n", address);
        fflush(stdout);
        DumpHex(address, 64);
    #endif
    for (struct { unsigned char* p; unsigned int i; } s = { (unsigned char*)address, 0 }; s.p < (unsigned char*)address + size; s.p++, s.i++) {
        unsigned char currentKey = ((unsigned char*)&key)[s.i % 4];
        *(s.p) ^= currentKey;
    }

    #ifdef _DEBUG_
        wprintf(L"xor32: after xor 0x%p:\n", address);
        fflush(stdout);
        DumpHex(address, 64);
    #endif
}

BOOL is_shellcode_thread(void* address) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        #ifdef _DEBUG_
            print_protection(address, mbi.Protect);
            print_type(address, mbi.Type);
        #endif
        return mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE;
    } else {
        #ifdef _DEBUG_
            wprintf(L"get_allocation_base_from_pointer: cannot get protection for 0x%p\n", address);
            fflush(stdout);
        #endif
        ExitProcess(-1);
    }
}

void* get_allocation_base_from_pointer(void* address) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (!VirtualQuery(address, &mbi, sizeof(mbi))) {
        #ifdef _DEBUG_
            wprintf(L"get_allocation_base_from_pointer: cannot get allocation base for 0x%p\n", address);
            fflush(stdout);
        #endif
        ExitProcess(-1);
    }

    return mbi.AllocationBase;
}

SIZE_T get_region_size_from_pointer(void* address) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (!VirtualQuery(address, &mbi, sizeof(mbi))) {
        #ifdef _DEBUG_
            wprintf(L"get_region_size_from_pointer: cannot get region size for 0x%p\n", address);
            fflush(stdout);
        #endif
        ExitProcess(-1);
    }
    return (unsigned char*)mbi.BaseAddress - (unsigned char*)mbi.AllocationBase + mbi.RegionSize;
}

unsigned int get_protection_from_pointer(void* address) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (!VirtualQuery(address, &mbi, sizeof(mbi))) {
        #ifdef _DEBUG_
            wprintf(L"get_region_size_from_pointer: cannot get protection for 0x%p\n", address);
            fflush(stdout);
        #endif
        ExitProcess(-1);
    }

    return mbi.Protect;
}

void xor_region_and_change_protection(void* address, unsigned int key, DWORD newProtection) {
    DWORD oldProt = 0;
    void* allocation_base = get_allocation_base_from_pointer(address);
    SIZE_T region_size = get_region_size_from_pointer(address);

    #ifdef _DEBUG_
        wprintf(L"xor_region_and_change_protection: xoring 0x%p (base: 0x%p, length: %d) with key 0x%x (new protection: %d)\n", address, allocation_base, region_size, key, newProtection);
        fflush(stdout);
    #endif

    if (!VirtualProtect(allocation_base, region_size, PAGE_READWRITE, &oldProt)) {
        #ifdef _DEBUG_
            wprintf(L"xor_region_and_change_protection: cannot change protection (PAGE_READWRITE) for 0x%p, %d (last error: 0x%x)\n", allocation_base, region_size, GetLastError());
            fflush(stdout);
        #endif
        if (!VirtualProtect(allocation_base, region_size, PAGE_EXECUTE_WRITECOPY, &oldProt)) {
            #ifdef _DEBUG_
                wprintf(L"xor_region_and_change_protection: cannot change protection (PAGE_EXECUTE_WRITECOPY) for 0x%p, %d (last error: 0x%x)\n", allocation_base, region_size, GetLastError());
                fflush(stdout);
            #endif

            ExitProcess(-1);
        } else if (newProtection == PAGE_READWRITE) {
            newProtection = PAGE_EXECUTE_WRITECOPY;
        }
    }

    FlushInstructionCache((HANDLE)-1, allocation_base, region_size);
    xor32(allocation_base, region_size, key);

    if (!VirtualProtect(allocation_base, region_size, newProtection, &oldProt)) {
        #ifdef _DEBUG_
            wprintf(L"xor_region_and_change_protection: cannot change protection for 0x%p, %d (last error: 0x%x)\n", allocation_base, region_size, GetLastError());
            fflush(stdout);
        #endif
        ExitProcess(-1);
    }

    FlushInstructionCache((HANDLE)-1, allocation_base, region_size);
}

void inline_hook_function(BOOL enable, char* addressToHook, void* jumpAddress) {
#ifdef _WIN64
    unsigned char trampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    memcpy(&trampoline[2], &jumpAddress, sizeof(jumpAddress));
#else
    unsigned char trampoline[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, addr
        0xFF, 0xE0                        // jmp eax
    };

    memcpy(&trampoline[1], &jumpAddress, sizeof(jumpAddress));
#endif

    DWORD trampolineLength = sizeof(trampoline);
    DWORD oldProt = 0;

    if (VirtualProtect(addressToHook, trampolineLength, PAGE_EXECUTE_READWRITE, &oldProt)) {
        if (enable) {
            memcpy(originalBytes, addressToHook, trampolineLength);
            memcpy(addressToHook, trampoline, trampolineLength);
        } else {
            memcpy(addressToHook, originalBytes, trampolineLength);
        }
    } else {
        #ifdef _DEBUG_
            wprintf(L"inline_hook_function: cannot change protection for 0x%p\n", addressToHook);
            fflush(stdout);
        #endif
        ExitProcess(-1);
    }

    FlushInstructionCache((HANDLE)-1, addressToHook, trampolineLength);

    if (!VirtualProtect(addressToHook, trampolineLength, oldProt, &oldProt)) {
        #ifdef _DEBUG_
            wprintf(L"inline_hook_function: cannot change protection for 0x%p\n", addressToHook);
            fflush(stdout);
        #endif
        ExitProcess(-1);
    }
}

#ifdef FLUCTUATE_NA
LONG VEHHandler(PEXCEPTION_POINTERS pExceptInfo) {
    #ifdef _WIN64
        void* caller = (void*)pExceptInfo->ContextRecord->Rip;
    #else
        void* caller = (void*)pExceptInfo->ContextRecord->Eip;
    #endif
    if (pExceptInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION /*0xc0000005*/) {
        #ifdef _DEBUG_
            wprintf(L"VEHHandler: STATUS_ACCESS_VIOLATION at 0x%p\n", caller);
            fflush(stdout);
        #endif

        if (is_shellcode_thread(caller)) {
            #ifdef _DEBUG_
                puts("VEHHandler: restoring original protection");
                fflush(stdout);
            #endif

            xor_region_and_change_protection(caller, XOR_KEY, originalProtection);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    #ifdef _DEBUG_
        wprintf(L"unhandled exception: 0x%x\n", pExceptInfo->ExceptionRecord->ExceptionCode);
        fflush(stdout);
    #endif

    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

void hook_sleep(BOOL enable);

void my_sleep(DWORD dwMilliseconds) {
    // const LPVOID caller = _ReturnAddress();
    void* caller = __builtin_extract_return_addr(__builtin_return_address(0));
    // PULONG_PTR overwrite = (PULONG_PTR)_AddressOfReturnAddress();
    //unsigned int* overwrite = *((unsigned int**)__builtin_frame_address(0)) + 1;

    #ifdef _DEBUG_
        wprintf(L"my_sleep: called with %d milliseconds by 0x%p\n", dwMilliseconds, caller);
        fflush(stdout);
    #endif

    if (is_shellcode_thread(caller)) {
        #ifdef _DEBUG_
            wprintf(L"my_sleep: caller 0x%p is from shellcode\n", caller);
            fflush(stdout);
        #endif
        originalProtection = get_protection_from_pointer(caller);
        #ifdef FLUCTUATE_RW
            xor_region_and_change_protection(caller, XOR_KEY, PAGE_READWRITE);
        #elif FLUCTUATE_NA
            xor_region_and_change_protection(caller, XOR_KEY, PAGE_NOACCESS);
        #endif
    }

    hook_sleep(FALSE);

    #ifdef _DEBUG_
        wprintf(L"my_sleep: sleeping for %d milliseconds\n", dwMilliseconds);
        fflush(stdout);
    #endif

    Sleep(dwMilliseconds);

    if (is_shellcode_thread(caller)) {
        #ifdef FLUCTUATE_RW
            xor_region_and_change_protection(caller, XOR_KEY, originalProtection);
        #endif
    }

    hook_sleep(TRUE);
}

void hook_sleep(BOOL enable) {
    inline_hook_function(enable, (char*)&Sleep, (void*)&my_sleep);
}

void register_vectored_handler() {
    #ifdef FLUCTUATE_NA
        #ifdef _DEBUG_
            puts("register_vectored_handler: adding vectored exception handler");
        #endif
        AddVectoredExceptionHandler(1, &VEHHandler);
    #endif
}

void fluctuate() {
    XOR_KEY = generate_random_int();
    #ifdef FLUCTUATE_NA
        register_vectored_handler();
    #endif
    #ifdef _DEBUG_
        puts("fluctuate: hooking Sleep");
    #endif
    hook_sleep(TRUE);
}
