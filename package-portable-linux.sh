#!/bin/sh
## targeting old glibc
# docker run --mount type=bind,source="$(pwd)",target="/usr/src/app" -it ubuntu:16.04

cd /usr/src/app

# https://gist.github.com/jlblancoc/99521194aba975286c80f93e47966dc5
apt update
apt install -y software-properties-common
add-apt-repository -y ppa:ubuntu-toolchain-r/test

apt update
apt install -y pkgconf g++-7 python-pip

# cmake (via pip)
python -m pip install cmake

# use gcc7
update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-7 100
update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-7 100

mkdir build-portable/ && cd build-portable/
/usr/local/bin/cmake .. -DBUILD_PORTABLE_LINUX=1 -DBUILD_LIBSODIUM=1
make -j5 install
