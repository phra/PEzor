#!/usr/bin/env bash

CURR_DIR=`pwd`
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd $INSTALL_DIR &&

apt update &&
apt install -y wget unzip build-essential cmake autotools-dev git clang golang mingw-w64 libcapstone-dev libssl-dev cowsay mono-devel &&

mkdir -p deps &&
cd deps &&

(ls inline_syscall 2>/dev/null 1>&2 || (
    git clone https://github.com/JustasMasiulis/inline_syscall.git &&
    cd inline_syscall &&
    git checkout 24238544b510d8f85ca38de3a43bc41fa8cfe380 &&
    cd .. &&
    grep -v '#include <intrin.h>' $INSTALL_DIR/deps/inline_syscall/include/in_memory_init.hpp > $INSTALL_DIR/deps/inline_syscall/include/in_memory_init.hpp2 &&
    mv $INSTALL_DIR/deps/inline_syscall/include/in_memory_init.hpp2 $INSTALL_DIR/deps/inline_syscall/include/in_memory_init.hpp)
) &&

(ls donut 2>/dev/null 1>&2 || (git clone https://github.com/TheWover/donut.git && cd donut && git checkout b70467e &&
make )
) &&

(ls keystone 2>/dev/null 1>&2 || (git clone --depth 1 https://github.com/keystone-engine/keystone.git &&
cd keystone &&
mkdir -p build &&
cd build &&
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="X86" -G "Unix Makefiles" .. &&
make &&
make install &&
cd ../..)
) &&

go get github.com/EgeBalci/sgn &&

(ls wclang 2>/dev/null 1>&2 || (git clone --depth 1 https://github.com/tpoechtrager/wclang.git &&
cd wclang &&
cmake -DCMAKE_INSTALL_PREFIX=_prefix_PEzor_ . &&
make &&
make install &&
cd ..)
) &&

cd .. &&

wget https://www.cobaltstrike.com/downloads/beacon.h &&

(grep -q _prefix_PEzor_ ~/.bashrc || echo "export PATH=\$PATH:~/go/bin/:$INSTALL_DIR:$INSTALL_DIR/deps/donut/:$INSTALL_DIR/deps/wclang/_prefix_PEzor_/bin/") >> ~/.bashrc &&

export PATH=$PATH:~/go/bin/:$INSTALL_DIR:$INSTALL_DIR/deps/donut/:$INSTALL_DIR/deps/wclang/_prefix_PEzor_/bin/ &&

ln -fs $INSTALL_DIR/PEzor.sh $INSTALL_DIR/PEzor &&

chmod +x $INSTALL_DIR/PEzor &&

$INSTALL_DIR/PEzor.sh -h &&

cd $CURR_DIR &&

echo '[!] installation complete' &&
echo '[?] run the following command to update $PATH variable or restart your shell' &&
echo "export PATH=\$PATH:~/go/bin/:$INSTALL_DIR:$INSTALL_DIR/deps/donut/:$INSTALL_DIR/deps/wclang/_prefix_PEzor_/bin/"
