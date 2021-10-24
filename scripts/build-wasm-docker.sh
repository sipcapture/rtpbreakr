#!/bin/bash -x

EM_VERSION=1.39.18-upstream

docker pull trzeci/emscripten:$EM_VERSION
docker run \
  -v $PWD:/src \
  -v $PWD/cache-wasm:/emsdk_portable/.data/cache/wasm \
  trzeci/emscripten:$EM_VERSION \
  sh -c 'bash ./build-wasm.sh'
