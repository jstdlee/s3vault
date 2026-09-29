#!/usr/bin/env bash
# One-shot build: fetch deps, fetch X11/GL headers locally if missing, compile.
set -euo pipefail
cd "$(dirname "$0")"
scripts/fetch-deps.sh
if [ ! -f /usr/include/X11/Xlib.h ] || [ ! -f /usr/include/X11/extensions/Xrandr.h ]; then
    [ -f third_party/sysroot/usr/include/X11/Xlib.h ] || scripts/bootstrap-headers.sh
fi
cmake -S . -B build -DCMAKE_BUILD_TYPE="${BUILD_TYPE:-Release}"
cmake --build build -j"$(nproc)"
echo "Built: $(pwd)/build/s3vault $(pwd)/build/s3vault-cli"
