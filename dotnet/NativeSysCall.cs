//
// Author: B4rtik (@b4rtik)
// Project: Injector
// License: BSD 3-Clause
//

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using static Injector.Natives;

namespace Injector
{
    class NativeSysCall
    {
        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwUnMapViewOfSection(IntPtr hSection, IntPtr address);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwCreateSection(out IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);
            
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int LdrLoadDll(IntPtr PathToFile,
                UInt32 dwFlags,
                ref Natives.UNICODE_STRING ModuleFileName,
                ref IntPtr ModuleHandle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr CreateThread(
                UInt32 lpThreadAttributes,
                UInt32 dwStackSize,
                IntPtr lpStartAddress,
                IntPtr param,
                UInt32 dwCreationFlags,
                ref UInt32 lpThreadId);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate UInt32 WaitForSingleObject(
                IntPtr hHandle,
                UInt32 dwMilliseconds);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool VirtualProtectEx(
                IntPtr hProcess,
                IntPtr lpAddress,
                UIntPtr dwSize,
                uint newprotect,
                out uint oldprotect);
            
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr VirtualAlloc(
                UInt32 lpStartAddr,
                UInt32 size,
                UInt32 flAllocationType,
                UInt32 flProtect);
        }
    }
}
