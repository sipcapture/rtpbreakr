#!/bin/bash -x
set -e
set -o pipefail

# verify Emscripten version
emcc -v

if [ ! -d "./libpcap-1.9.1" ]
then
  apt-get update && apt-get install -y flex bison
  wget https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz
  tar xf libpcap-1.9.1.tar.gz
  rm -rf libpcap-1.9.1.tar.gz
  cd libpcap-1.9.1
  emconfigure ./configure --with-pcap=null && emmake make && emmake make install
  find -name "libpcap.so*" -o -name "libpcap.a"
  cd ..
fi

if [ ! -d "./libnet-1.2" ]
then
  apt update && apt install -y dh-autoreconf
  wget https://github.com/libnet/libnet/releases/download/v1.2/libnet-1.2.tar.gz
  tar xf libnet-1.2.tar.gz
  rm -rf xf libnet-1.2.tar.gz
  ls -alF
  cd libnet-1.2
  sed -i 's/__int64/u_int64/g' libnet-1.2/include/libnet/libnet-structures.h
  ./autogen.sh
  emconfigure ./configure && emmake make && cmmake make install
  cd ..
fi


# build rtpbreakr.wasm
mkdir -p wasm/dist
cd src
ARGS=(
  -O3
  -s WASM=1
  -s ERROR_ON_UNDEFINED_SYMBOLS=0
  -s FORCE_FILESYSTEM=1
  -s ASSERTIONS=0
  -s FETCH=1
  -s EXIT_RUNTIME=1
  -s ALLOW_MEMORY_GROWTH=1
  -s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap", "FS"]'
#  -fno-rtti -fno-exceptions
  -I. -I../libpcap-1.9.1
  -L../libpcap-1.9.1
  -I../libnet-1.2/include
  -L../libnet-1.2
  -o ../wasm/dist/rtptool.js main.c common.c net.c -lpcap
)
emcc "${ARGS[@]}"
