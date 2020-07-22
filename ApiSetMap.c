/*************************************************************************************
*  Author: Jeff Tang <jtang@cylance.com>
*  Copyright (c) 2017 Cylance Inc. All rights reserved.                              *
*                                                                                    *
*  Redistribution and use in source and binary forms, with or without modification,  *
*  are permitted provided that the following conditions are met:                     *
*                                                                                    *
*  1. Redistributions of source code must retain the above copyright notice, this    *
*  list of conditions and the following disclaimer.                                  *
*                                                                                    *
*  2. Redistributions in binary form must reproduce the above copyright notice,      *
*  this list of conditions and the following disclaimer in the documentation and/or  *
*  other materials provided with the distribution.                                   *
*                                                                                    *
*  3. Neither the name of the copyright holder nor the names of its contributors     *
*  may be used to endorse or promote products derived from this software without     *
*  specific prior written permission.                                                *
*                                                                                    *
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND   *
*  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED     *
*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE            *
*  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR  *
*  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES    *
*  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;      *
*  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON    *
*  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT           *
*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS     *
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      *
*                                                                                    *
*************************************************************************************/

#include "ApiSetMap.h"

__PPEB GetProcessEnvironmentBlock()
{
    ULONG_PTR pPeb;
#ifdef _WIN64
    pPeb = __readgsqword(0x60);
#else
#ifdef WIN_ARM
    pPeb = *(DWORD *)( (BYTE *)_MoveFromCoprocessor( 15, 0, 13, 0, 2 ) + 0x30 );
#else
    // _WIN32
    pPeb = __readfsdword(0x30);
#endif
#endif
    return (__PPEB)pPeb;
}

__PLDR_DATA_TABLE_ENTRY GetInMemoryOrderModuleList()
{
    return (__PLDR_DATA_TABLE_ENTRY)GetProcessEnvironmentBlock()->pLdr->InMemoryOrderModuleList.Flink;
}

PWCHAR GetRedirectedName(const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
{
    PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetMap;
    pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V2)GetProcessEnvironmentBlock()->lpApiSetMap;
    *stSize = 0;

    if (pApiSetMap->Version == 6)
        return GetRedirectedName_V6(wszImportingModule, wszVirtualModule, stSize);
    else if (pApiSetMap->Version == 4)
        return GetRedirectedName_V4(wszImportingModule, wszVirtualModule, stSize);
    else if (pApiSetMap->Version == 2)
        return GetRedirectedName_V2(wszImportingModule, wszVirtualModule, stSize);
    else
        return NULL;
}

PWCHAR GetRedirectedName_V6(const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
{
    PAPI_SET_NAMESPACE_ARRAY_V6 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V6 pApiEntry;
    PAPI_SET_VALUE_ENTRY_V6 pApiValue;
    PAPI_SET_VALUE_ENTRY_V6 pApiArray;
    DWORD dwEntryCount;
    LONG dwSetCount;
    PWSTR wsEntry;
    PWSTR wsName;
    PWSTR wsValue;

    pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V6)GetProcessEnvironmentBlock()->lpApiSetMap;

    // Loop through each entry in the ApiSetMap to find the matching redirected module entry
    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        wsEntry = (PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset);

        // Skip this entry if it does not match
        if (_wcsnicmp(wsEntry, wszVirtualModule, pApiEntry->NameLength / 2) != 0)
            continue;

        pApiArray = (PAPI_SET_VALUE_ENTRY_V6)((PCHAR)pApiSetMap + pApiEntry->DataOffset);

        // Loop through each value entry from the end and find where the importing module matches the ``Name`` entry
        // If the ``Name`` entry is empty, it is the default entry @ index = 0
        for (dwSetCount = pApiEntry->Count-1; dwSetCount >= 0; dwSetCount--)
        {
           // pApiValue = (PAPI_SET_VALUE_ENTRY_V6)((PCHAR)pApiSetMap + pApiEntry->DataOffset + (dwSetCount * sizeof(API_SET_VALUE_ENTRY_V6)));
            pApiValue = &pApiArray[dwSetCount];
            wsName = (PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset);
            wsValue = (PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset);

            if (pApiValue->NameLength == 0 || _wcsnicmp(wsName, wszImportingModule, pApiValue->NameLength / 2) == 0)
            {
                *stSize = pApiValue->ValueLength / 2;
                return wsValue;
            }
        }
    }
    return NULL;
}


PWCHAR GetRedirectedName_V4(const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
{
    PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V4 pApiEntry;
    PAPI_SET_VALUE_ARRAY_V4 pApiArray;
    PAPI_SET_VALUE_ENTRY_V4 pApiValue;
    DWORD dwEntryCount;
    LONG dwSetCount;
    PWSTR wsEntry;
    PWSTR wsName;
    PWSTR wsValue;


    pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V4)GetProcessEnvironmentBlock()->lpApiSetMap;
    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        wsEntry = (PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset);

        if (_wcsnicmp(wsEntry, wszVirtualModule, pApiEntry->NameLength / 2) != 0)
            continue;

        pApiArray = (PAPI_SET_VALUE_ARRAY_V4)((PCHAR)pApiSetMap + pApiEntry->DataOffset);

        for (dwSetCount = pApiArray->Count-1; dwSetCount >= 0; dwSetCount--)
        {
            pApiValue = &pApiArray->Array[dwSetCount];
            wsName = (PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset);
            wsValue = (PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset);

            if (pApiValue->NameLength == 0 || _wcsnicmp(wsName, wszImportingModule, pApiValue->NameLength / 2) == 0)
            {
                *stSize = pApiValue->ValueLength / 2;
                return wsValue;
            }
        }
    }
    return NULL;
}

PWCHAR GetRedirectedName_V2(const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
{
    PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V2 pApiEntry;
    PAPI_SET_VALUE_ARRAY_V2 pApiArray;
    PAPI_SET_VALUE_ENTRY_V2 pApiValue;
    DWORD dwEntryCount;
    LONG dwSetCount;
    PWSTR wsEntry;
    PWSTR wsName;
    PWSTR wsValue;


    pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V2)GetProcessEnvironmentBlock()->lpApiSetMap;

    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        wsEntry = (PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset);

        if (_wcsnicmp(wsEntry, wszVirtualModule, pApiEntry->NameLength / 2) != 0)
            continue;

        pApiArray = (PAPI_SET_VALUE_ARRAY_V2)((PCHAR)pApiSetMap + pApiEntry->DataOffset);

        for (dwSetCount = pApiArray->Count-1; dwSetCount >= 0; dwSetCount--)
        {
            pApiValue = &pApiArray->Array[dwSetCount];
            wsName = (PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset);
            wsValue = (PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset);

            if (pApiValue->NameLength == 0 || _wcsnicmp(wsName, wszImportingModule, pApiValue->NameLength / 2) == 0)
            {
                *stSize = pApiValue->ValueLength / 2;
                return wsValue;
            }
        }
    }
    return NULL;
}
