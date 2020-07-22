#!/usr/bin/env bash

CURR_DIR=`pwd`
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd $INSTALL_DIR &&

apt update &&
apt install -y wget unzip build-essential cmake autotools-dev git clang golang mingw-w64 libcapstone-dev libssl-dev cowsay &&

mkdir -p deps &&
cd deps &&

(ls inline_syscall 2>/dev/null 1>&2 || (
    git clone --depth 1 https://github.com/JustasMasiulis/inline_syscall.git &&
    grep -v '#include <intrin.h>' $INSTALL_DIR/deps/inline_syscall/include/in_memory_init.hpp > $INSTALL_DIR/deps/inline_syscall/include/in_memory_init.hpp2 &&
    mv $INSTALL_DIR/deps/inline_syscall/include/in_memory_init.hpp2 $INSTALL_DIR/deps/inline_syscall/include/in_memory_init.hpp)
) &&

(ls donut_v0.9.3.tar.gz 2>/dev/null 1>&2 || (wget https://github.com/TheWover/donut/releases/download/v0.9.3/donut_v0.9.3.tar.gz &&
tar xvf donut_v0.9.3.tar.gz)
) &&

(ls keystone 2>/dev/null 1>&2 || (git clone --depth 1 https://github.com/keystone-engine/keystone.git &&
cd keystone &&
mkdir -p build &&
cd build &&
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="X86" -G "Unix Makefiles" .. &&
make -j &&
make install &&
cd ../..)
) &&

go get github.com/egebalci/sgn &&

(ls wclang 2>/dev/null 1>&2 || (git clone --depth 1 https://github.com/tpoechtrager/wclang.git &&
cd wclang &&
cmake -DCMAKE_INSTALL_PREFIX=_prefix_PEzor_ . &&
make &&
make install &&
cd ..)
) &&

cd .. &&

(grep -q _prefix_PEzor_ ~/.bashrc || echo "export PATH=\$PATH:~/go/bin/:$INSTALL_DIR:$INSTALL_DIR/deps/donut_v0.9.3/:$INSTALL_DIR/deps/wclang/_prefix_PEzor_/bin/") >> ~/.bashrc &&

export PATH=$PATH:~/go/bin/:$INSTALL_DIR:$INSTALL_DIR/deps/donut_v0.9.3/:$INSTALL_DIR/deps/wclang/_prefix_PEzor_/bin/ &&

ln -fs $INSTALL_DIR/PEzor.sh $INSTALL_DIR/PEzor &&

chmod +x $INSTALL_DIR/PEzor &&

$INSTALL_DIR/PEzor.sh -h &&

cd $CURR_DIR &&

echo '[!] installation complete' &&
echo '[?] run the following command to update $PATH variable or restart your shell' &&
echo "export PATH=\$PATH:~/go/bin/:$INSTALL_DIR:$INSTALL_DIR/deps/donut_v0.9.3/:$INSTALL_DIR/deps/wclang/_prefix_PEzor_/bin/"
