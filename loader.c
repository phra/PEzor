#include "loader.h"
#include "stdio.h"

void RefreshPE()
{
    HMODULE hModule;
    PWSTR wszFullDllName;
    PWSTR wszBaseDllName;
    ULONG_PTR pDllBase;

    __PLDR_DATA_TABLE_ENTRY pLdteHead = NULL;
    __PLDR_DATA_TABLE_ENTRY pLdteCurrent = NULL;

    OUTPUTDBGA("[*] Running DLLRefresher\n");

    pLdteHead = GetInMemoryOrderModuleList();
    pLdteCurrent = pLdteHead;

    do {
        if (pLdteCurrent->FullDllName.Length > 2)
        {
            wszFullDllName = pLdteCurrent->FullDllName.Buffer;
            wszBaseDllName = pLdteCurrent->BaseDllName.Buffer;
            pDllBase = (ULONG_PTR)pLdteCurrent->DllBase;

            OUTPUTDBGA("[*] Refreshing DLL: ");
            OUTPUTDBGW(wszBaseDllName);
            OUTPUTDBGA("\n");

            hModule = CustomLoadLibrary(wszFullDllName, wszBaseDllName, pDllBase);

            if (hModule)
            {
                ScanAndFixModule((PCHAR)hModule, (PCHAR)pDllBase, wszBaseDllName);
                VirtualFree(hModule, 0, MEM_RELEASE);
            }
        }
        pLdteCurrent = (__PLDR_DATA_TABLE_ENTRY)pLdteCurrent->InMemoryOrderModuleList.Flink;
    } while (pLdteCurrent != pLdteHead);
}

HMODULE CustomLoadLibrary(const PWCHAR wszFullDllName, const PWCHAR wszBaseDllName, ULONG_PTR pDllBase)
{
    // File handles
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
    PCHAR pFile = NULL;

    // PE headers
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;

    // Library 
    PCHAR pLibraryAddr = NULL;
    DWORD dwIdx;

    // Relocation
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_BASE_RELOCATION pBaseReloc;
    ULONG_PTR pReloc;
    DWORD dwNumRelocs;
    ULONG_PTR pInitialImageBase;
    PIMAGE_RELOC pImageReloc;

    // Import
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PCHAR szDllName;
    SIZE_T stDllName;
    PWSTR wszDllName = NULL;
    PWCHAR wsRedir = NULL;
    // PWSTR wszRedirName = NULL;
    SIZE_T stRedirName;
    size_t stSize;

    HMODULE hModule;
    PIMAGE_THUNK_DATA pThunkData;
    FARPROC* pIatEntry;

    // ----
    // Step 1: Map the file into memory
    // ----
    OUTPUTDBGA("[+] Opening file: ");
    OUTPUTDBGW(wszFullDllName);
    OUTPUTDBGA("\n");

    hFile = CreateFileW(wszFullDllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        goto cleanup;

    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap == NULL)
        goto cleanup;

    pFile = (PCHAR)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (pFile == NULL)
        goto cleanup;

    // ----
    // Step 2: Parse the file headers and load it into memory
    // ----
    pDosHeader = (PIMAGE_DOS_HEADER)pFile;
    pNtHeader = (PIMAGE_NT_HEADERS)(pFile + pDosHeader->e_lfanew);

    // allocate memory to copy DLL into
    OUTPUTDBGA("\t[+] Allocating memory for library\n");
    pLibraryAddr = (PCHAR)VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy header
    OUTPUTDBGA("\t[+] Copying PE header into memory\n");
    memcpy(pLibraryAddr, pFile, pNtHeader->OptionalHeader.SizeOfHeaders);

    // copy sections
    OUTPUTDBGA("\t[+] Copying PE sections into memory\n");
    pSectionHeader = (PIMAGE_SECTION_HEADER)(pFile + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (dwIdx = 0; dwIdx < pNtHeader->FileHeader.NumberOfSections; dwIdx++)
    {
        memcpy(pLibraryAddr + pSectionHeader[dwIdx].VirtualAddress,
               pFile + pSectionHeader[dwIdx].PointerToRawData,
               pSectionHeader[dwIdx].SizeOfRawData);
    }

    // update our pointers to the loaded image
    pDosHeader = (PIMAGE_DOS_HEADER)pLibraryAddr;
    pNtHeader = (PIMAGE_NT_HEADERS)(pLibraryAddr + pDosHeader->e_lfanew);

    // ----
    // Step 3: Calculate relocations
    // ----
    OUTPUTDBGA("\t[+] Calculating file relocations\n");

    pDataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pInitialImageBase = pNtHeader->OptionalHeader.ImageBase;
    
    // set the ImageBase to the already loaded module's base
    pNtHeader->OptionalHeader.ImageBase = pDllBase;

    // check if their are any relocations present
    if (pDataDir->Size)
    {
        // calculate the address of the first IMAGE_BASE_RELOCATION entry
        pBaseReloc = (PIMAGE_BASE_RELOCATION)(pLibraryAddr + pDataDir->VirtualAddress);

        // iterate through each relocation entry
		while ((PCHAR)pBaseReloc < (pLibraryAddr + pDataDir->VirtualAddress + pDataDir->Size) && pBaseReloc->SizeOfBlock)
		{
            // the VA for this relocation block
            pReloc = (ULONG_PTR)(pLibraryAddr + pBaseReloc->VirtualAddress);

            // number of entries in this relocation block
            dwNumRelocs = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

            // first entry in the current relocation block
            pImageReloc = (PIMAGE_RELOC)((PCHAR)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

            // iterate through each entry in the relocation block
            while (dwNumRelocs--)
            {
                // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                // we subtract the initial ImageBase and add in the original dll base
                if (pImageReloc->type == IMAGE_REL_BASED_DIR64)
                {
                    *(ULONG_PTR *)(pReloc + pImageReloc->offset) -= pInitialImageBase;
                    *(ULONG_PTR *)(pReloc + pImageReloc->offset) += pDllBase;
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGHLOW)
                {
                    *(DWORD *)(pReloc + pImageReloc->offset) -= (DWORD)pInitialImageBase;
                    *(DWORD *)(pReloc + pImageReloc->offset) += (DWORD)pDllBase;
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGH)
                {
                    *(WORD *)(pReloc + pImageReloc->offset) -= HIWORD(pInitialImageBase);
                    *(WORD *)(pReloc + pImageReloc->offset) += HIWORD(pDllBase);
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_LOW)
                {
                    *(WORD *)(pReloc + pImageReloc->offset) -= LOWORD(pInitialImageBase);
                    *(WORD *)(pReloc + pImageReloc->offset) += LOWORD(pDllBase);
                }
                
                // get the next entry in the current relocation block
                pImageReloc = (PIMAGE_RELOC)((PCHAR)pImageReloc + sizeof(IMAGE_RELOC));
            }

            // get the next entry in the relocation directory
            pBaseReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pBaseReloc + pBaseReloc->SizeOfBlock);
        }
    }

    // ----
    // Step 4: Update import table
    // ----
    OUTPUTDBGA("\t[+] Resolving Import Address Table (IAT) \n");

    pDataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pDataDir->Size)
    {
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pLibraryAddr + pDataDir->VirtualAddress);

        while (pImportDesc->Characteristics)
        {
            hModule = NULL;
            wszDllName = NULL;
            szDllName = (PCHAR)(pLibraryAddr + pImportDesc->Name);
            stDllName = strnlen(szDllName, MAX_PATH);
            wszDllName = (PWSTR)calloc(stDllName + 1, sizeof(WCHAR));

            if (wszDllName == NULL)
                goto next_import;

            mbstowcs_s(&stSize, wszDllName, stDllName + 1, szDllName, stDllName);

            OUTPUTDBGA("\t\t[+] Loading library: ");
            OUTPUTDBGW(wszDllName);
            OUTPUTDBGA("\n");

            // If the DLL starts with api- or ext-, resolve the redirected name and load it
            if (_wcsnicmp(wszDllName, L"api-", 4) == 0 || _wcsnicmp(wszDllName, L"ext-", 4) == 0)
            {
                // wsRedir is not null terminated
                wsRedir = GetRedirectedName(wszBaseDllName, wszDllName, &stRedirName);
                if (wsRedir)
                {
                    // Free the original wszDllName and allocate a new buffer for the redirected dll name
                    free(wszDllName);
                    wszDllName = (PWSTR)calloc(stRedirName + 1, sizeof(WCHAR));
                    if (wszDllName == NULL)
                        goto next_import;

                    memcpy(wszDllName, wsRedir, stRedirName * sizeof(WCHAR));
                }
            }

            // Load the module
            hModule = CustomGetModuleHandleW(wszDllName);

            // Ignore libraries that fail to load
            if (hModule == NULL)
                goto next_import;

            if (pImportDesc->OriginalFirstThunk)
                pThunkData = (PIMAGE_THUNK_DATA)(pLibraryAddr + pImportDesc->OriginalFirstThunk);
            else
                pThunkData = (PIMAGE_THUNK_DATA)(pLibraryAddr + pImportDesc->FirstThunk);

            pIatEntry = (FARPROC*)(pLibraryAddr + pImportDesc->FirstThunk);

            // loop through each thunk and resolve the import
            for(; DEREF(pThunkData); pThunkData++, pIatEntry++)
            {
                if (IMAGE_SNAP_BY_ORDINAL(pThunkData->u1.Ordinal))
                    *pIatEntry = CustomGetProcAddressEx(hModule, (PCHAR)IMAGE_ORDINAL(pThunkData->u1.Ordinal), wszDllName);
                else
                    *pIatEntry = CustomGetProcAddressEx(hModule, ((PIMAGE_IMPORT_BY_NAME)(pLibraryAddr + DEREF(pThunkData)))->Name, wszDllName);
            }

next_import:
            if (wszDllName != NULL)
            {
                free(wszDllName);
                wszDllName = NULL;
            }
            pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)pImportDesc + sizeof(IMAGE_IMPORT_DESCRIPTOR));

        }
    }

cleanup:
    if (pFile != NULL)
        UnmapViewOfFile(pFile);
    if (hMap != NULL)
        CloseHandle(hMap);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    return (HMODULE) pLibraryAddr;
}

HMODULE CustomGetModuleHandleW(const PWSTR wszModule)
{
    // HMODULE hModule = NULL;
    __PLDR_DATA_TABLE_ENTRY pLdteHead = NULL;
    __PLDR_DATA_TABLE_ENTRY pLdteCurrent = NULL;

    OUTPUTDBGA("\t\t\t[*] Searching for loaded module: ");
    OUTPUTDBGW(wszModule);
    OUTPUTDBGA(" -> ");

    pLdteCurrent = pLdteHead = GetInMemoryOrderModuleList();

    do {
        if (pLdteCurrent->FullDllName.Length > 2 &&
            _wcsnicmp(wszModule, pLdteCurrent->BaseDllName.Buffer, pLdteCurrent->BaseDllName.Length / 2) == 0)
        {
            OUTPUTDBGA("found in memory\n");
            return ((HMODULE)pLdteCurrent->DllBase);
        }
        pLdteCurrent = (__PLDR_DATA_TABLE_ENTRY)pLdteCurrent->InMemoryOrderModuleList.Flink;
    } while (pLdteCurrent != pLdteHead);

    OUTPUTDBGA("loading from disk\n");
    return LoadLibraryW(wszModule);
}

VOID ScanAndFixModule(PCHAR pKnown, PCHAR pSuspect, PWCHAR wszBaseDllName)
{
    // PE headers
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;

    DWORD dwIdx;

    OUTPUTDBGA("[*] Scanning module: ");
    OUTPUTDBGW(wszBaseDllName);
    OUTPUTDBGA("\n");

    pDosHeader = (PIMAGE_DOS_HEADER)pKnown;
    pNtHeader = (PIMAGE_NT_HEADERS)(pKnown + pDosHeader->e_lfanew);

    // Scan PE header
    ScanAndFixSection("Header", pKnown, pSuspect, pNtHeader->OptionalHeader.SizeOfHeaders);

    // Scan each section
    pSectionHeader = (PIMAGE_SECTION_HEADER)(pKnown + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (dwIdx = 0; dwIdx < pNtHeader->FileHeader.NumberOfSections; dwIdx++)
    {

        // Skip writable sections
        if (pSectionHeader[dwIdx].Characteristics & IMAGE_SCN_MEM_WRITE)
            continue;

        ScanAndFixSection((PCHAR)pSectionHeader[dwIdx].Name, pKnown + pSectionHeader[dwIdx].VirtualAddress,
                          pSuspect + pSectionHeader[dwIdx].VirtualAddress, pSectionHeader[dwIdx].Misc.VirtualSize);
    }
}

VOID ScanAndFixSection(PCHAR szSectionName, PCHAR pKnown, PCHAR pSuspect, size_t stLength)
{
    DWORD ddOldProtect;

    if (memcmp(pKnown, pSuspect, stLength) != 0)
    {
        OUTPUTDBGA("\t[!] Found modification in: ");
        OUTPUTDBGA(szSectionName);
        OUTPUTDBGA("\n");

        if (!VirtualProtect(pSuspect, stLength, PAGE_EXECUTE_READWRITE, &ddOldProtect))
            return;

        OUTPUTDBGA("\t[+] Copying known good section into memory.\n");
        memcpy(pSuspect, pKnown, stLength);

        if (!VirtualProtect(pSuspect, stLength, ddOldProtect, &ddOldProtect))
            OUTPUTDBGA("\t[!] Failed to reset memory permissions.\n");
    }
}


// This code is modified from Stephen Fewer's GetProcAddress implementation
//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
FARPROC WINAPI CustomGetProcAddressEx(HMODULE hModule, const PCHAR lpProcName, PWSTR wszOriginalModule)
{
    UINT_PTR uiLibraryAddress = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    UINT_PTR uiFuncVA = 0;
    PCHAR cpExportedFunctionName;
    PCHAR szFwdDesc;
    PCHAR szRedirFunc;
    PWSTR wszDllName;
    SIZE_T stDllName;
    PWCHAR wsRedir;
    //PWSTR wszRedirName = NULL;
    SIZE_T stRedirName;

    HMODULE hFwdModule;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
    FARPROC fpResult = NULL;
    DWORD dwCounter;

    if (hModule == NULL)
        return NULL;

    // a module handle is really its base address
    uiLibraryAddress = (UINT_PTR)hModule;

    // get the VA of the modules NT Header
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

    pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // get the VA of the export directory
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

    // get the VA for the array of addresses
    uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

    // get the VA for the array of name pointers
    uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

    // get the VA for the array of name ordinals
    uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

    // test if we are importing by name or by ordinal...
    // #pragma warning(suppress: 4311)
    if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
    {
        // import by ordinal...

        // use the import ordinal (- export ordinal base) as an index into the array of addresses
        // #pragma warning(suppress: 4311)
        uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

        // resolve the address for this imported function
        fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
    }
    else
    {
        // import by name...
        dwCounter = pExportDirectory->NumberOfNames;
        while (dwCounter--)
        {
            cpExportedFunctionName = (PCHAR)(uiLibraryAddress + DEREF_32(uiNameArray));

            // test if we have a match...
            if (strcmp(cpExportedFunctionName, lpProcName) == 0)
            {
                // use the functions name ordinal as an index into the array of name pointers
                uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
                uiFuncVA = DEREF_32(uiAddressArray);

                // check for redirected exports
                if (pDataDirectory->VirtualAddress <= uiFuncVA && uiFuncVA < (pDataDirectory->VirtualAddress + pDataDirectory->Size))
                {
                    szFwdDesc = (PCHAR)(uiLibraryAddress + uiFuncVA);

                    OUTPUTDBGA("\t\t\t[*] Found a redirected entry: ");
                    OUTPUTDBGA(szFwdDesc);
                    OUTPUTDBGA("\n");

                    // Find the first character after "."
                    szRedirFunc = strstr(szFwdDesc, ".") + 1;
                    stDllName = (SIZE_T)(szRedirFunc - szFwdDesc);

                    // Allocate enough space to append "dll"
                    wszDllName = (PWSTR)calloc(stDllName + 3 + 1, sizeof(WCHAR));
                    if (wszDllName == NULL)
                        break;

                    mbstowcs_s(NULL, wszDllName, stDllName + 1, szFwdDesc, stDllName);
                    memcpy(wszDllName + stDllName, L"dll", 3 * sizeof(WCHAR));

                    // check for a redirected module name
                    if (_wcsnicmp(wszDllName, L"api-", 4) == 0 || _wcsnicmp(wszDllName, L"ext-", 4) == 0)
                    {
                        wsRedir = GetRedirectedName(wszOriginalModule, wszDllName, &stRedirName);
                        if (wsRedir)
                        {
                            // Free the original buffer and allocate a new one for the redirected dll name
                            free(wszDllName);

                            wszDllName = (PWSTR)calloc(stRedirName + 1, sizeof(WCHAR));
                            if (wszDllName == NULL)
                                break;

                            memcpy(wszDllName, wsRedir, stRedirName * sizeof(WCHAR));
                        }
                    }

                    hFwdModule = GetModuleHandleW(wszDllName);
                    fpResult = CustomGetProcAddressEx(hFwdModule, szRedirFunc, wszDllName);
                    free(wszDllName);
                }
                else
                {
                    // calculate the virtual address for the function
                    fpResult = (FARPROC)(uiLibraryAddress + uiFuncVA);
                }

                // finish...
                break;
            }

            // get the next exported function name
            uiNameArray += sizeof(DWORD);

            // get the next exported function name ordinal
            uiNameOrdinals += sizeof(WORD);
        }
    }

    return fpResult;
}
