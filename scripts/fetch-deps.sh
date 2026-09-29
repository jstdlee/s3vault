#!/usr/bin/env bash
# Fetch pinned third-party sources into third_party/.
set -euo pipefail
tp="$(cd "$(dirname "$0")/.." && pwd)/third_party"
mkdir -p "$tp"

IMGUI_REV=09f7a0f062b902dc0b377439421abc58d369b1d9   # 1.93 WIP (dynamic fonts), same as gpu-hud
GLFW_REV=7b6aead9fb88b3623e3b3725ebb42670cbe4c579    # 3.4
STB_REV=2c980bb59875b0d32144a71867fbdebb2f77cd20
PUGIXML_REV=db78afc2b7d8f043b4bc6b185635d949ea2ed2a8 # v1.14
CURL_REV=curl-8_5_0                                   # headers only; libcurl.so.4 is loaded at runtime
ICONS_REV=210b5a399a64270674560d633638952d1e8d804d   # IconFontCppHeaders
FA_TAG=6.5.2                                         # Font Awesome Free (solid)
SQLITE_ZIP=2024/sqlite-amalgamation-3460100.zip      # 3.46.1

fetch() {  # dir url rev
    if [ -d "$tp/$1/.git" ]; then return; fi
    git init -q "$tp/$1"
    git -C "$tp/$1" fetch -q --depth 1 "$2" "$3"
    git -C "$tp/$1" -c advice.detachedHead=false checkout -q FETCH_HEAD
}
get() {  # dest url
    [ -f "$1" ] || { mkdir -p "$(dirname "$1")"; curl -fsSL -o "$1.part" "$2"; mv "$1.part" "$1"; }
}

fetch imgui https://github.com/ocornut/imgui.git "$IMGUI_REV"
fetch glfw https://github.com/glfw/glfw.git "$GLFW_REV"
fetch pugixml https://github.com/zeux/pugixml.git "$PUGIXML_REV"
fetch icons https://github.com/juliettef/IconFontCppHeaders.git "$ICONS_REV"
get "$tp/stb/stb_image.h" "https://raw.githubusercontent.com/nothings/stb/$STB_REV/stb_image.h"
get "$tp/stb/stb_image_write.h" "https://raw.githubusercontent.com/nothings/stb/$STB_REV/stb_image_write.h"
get "$tp/fonts/fa-solid-900.ttf" "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/$FA_TAG/webfonts/fa-solid-900.ttf"
get "$tp/fonts/LICENSE-fontawesome.txt" "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/$FA_TAG/LICENSE.txt"

if [ ! -f "$tp/curl/include/curl/curl.h" ]; then
    for h in curl.h curlver.h easy.h header.h mprintf.h multi.h options.h system.h typecheck-gcc.h urlapi.h websockets.h; do
        get "$tp/curl/include/curl/$h" "https://raw.githubusercontent.com/curl/curl/$CURL_REV/include/curl/$h"
    done
fi

if [ ! -f "$tp/sqlite/sqlite3.c" ]; then
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/sqlite.zip" "https://www.sqlite.org/$SQLITE_ZIP"
    python3 -c 'import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$tmp/sqlite.zip" "$tmp"
    mkdir -p "$tp/sqlite"
    cp "$tmp"/sqlite-amalgamation-*/sqlite3.{c,h} "$tp/sqlite/"
    rm -rf "$tmp"
fi
echo "third_party ready"
