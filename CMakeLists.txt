cmake_minimum_required(VERSION 3.16)
project(s3vault CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(TP ${CMAKE_SOURCE_DIR}/third_party)
option(S3VAULT_GUI "Build the desktop GUI (ImGui + GLFW)" ON)

# Platform backend: only Linux is implemented; the others are reserved (see platform/*/README.md).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(S3V_PLATFORM linux)
else()
  message(FATAL_ERROR "s3vault: platform ${CMAKE_SYSTEM_NAME} is not implemented yet (see platform/)")
endif()

# ---- third-party (vendored sources) ----
add_library(sqlite3 STATIC ${TP}/sqlite/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${TP}/sqlite)
target_compile_definitions(sqlite3 PRIVATE SQLITE_THREADSAFE=1 SQLITE_DEFAULT_WAL_SYNCHRONOUS=1
                           SQLITE_OMIT_LOAD_EXTENSION SQLITE_DQS=0)
set_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(pugixml STATIC ${TP}/pugixml/src/pugixml.cpp)
target_include_directories(pugixml PUBLIC ${TP}/pugixml/src)

# ---- core (portable) ----
add_library(s3vault_core STATIC
  core/util/sha256.cpp core/util/strings.cpp core/util/subprocess.cpp core/util/fs.cpp core/util/secure.cpp
  core/config/config.cpp
  core/store/curl_dl.cpp core/store/sigv4.cpp core/store/s3_client.cpp
  core/crypto/gpg.cpp
  core/secret/strength.cpp core/secret/passcache.cpp
  core/index/db.cpp
  core/vault/vault.cpp
  core/sync/ignore.cpp core/sync/planner.cpp core/sync/engine.cpp
  core/preview/preview.cpp
  core/edit/edit.cpp
  # platform backend
  platform/${S3V_PLATFORM}/keychain_libsecret.cpp platform/${S3V_PLATFORM}/session_tmp.cpp
  platform/${S3V_PLATFORM}/desktop.cpp platform/${S3V_PLATFORM}/inotify_watcher.cpp)
target_include_directories(s3vault_core PUBLIC core core/include platform/iface ${TP}/curl/include)
target_link_libraries(s3vault_core PUBLIC sqlite3 pugixml ${CMAKE_DL_LIBS} pthread)
target_compile_options(s3vault_core PRIVATE -Wall -Wextra -Wno-unused-parameter)

# ---- CLI ----
add_executable(s3vault-cli cli/main.cpp)
target_link_libraries(s3vault-cli PRIVATE s3vault_core)

# ---- tests ----
add_executable(s3vault-tests tests/unit_tests.cpp)
target_link_libraries(s3vault-tests PRIVATE s3vault_core)
add_executable(s3vault-it-helper tests/it_helper.cpp)
target_link_libraries(s3vault-it-helper PRIVATE s3vault_core)

# ---- desktop GUI ----
if(S3VAULT_GUI)
  if(EXISTS ${TP}/sysroot/usr/include/X11/Xlib.h)
    include_directories(SYSTEM ${TP}/sysroot/usr/include)
    list(APPEND CMAKE_PREFIX_PATH ${TP}/sysroot/usr)
    set(CMAKE_REQUIRED_INCLUDES ${TP}/sysroot/usr/include)
  endif()
  set(GLFW_BUILD_WAYLAND OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_X11 ON CACHE BOOL "" FORCE)
  set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
  set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
  add_subdirectory(${TP}/glfw EXCLUDE_FROM_ALL)
  if(EXISTS ${TP}/sysroot/usr/include/X11/Xlib.h)
    target_include_directories(glfw PRIVATE ${TP}/sysroot/usr/include)
  endif()

  set(IMGUI ${TP}/imgui)
  add_library(imgui STATIC
    ${IMGUI}/imgui.cpp ${IMGUI}/imgui_draw.cpp ${IMGUI}/imgui_tables.cpp ${IMGUI}/imgui_widgets.cpp
    ${IMGUI}/backends/imgui_impl_glfw.cpp ${IMGUI}/backends/imgui_impl_opengl3.cpp)
  target_include_directories(imgui PUBLIC ${IMGUI})
  target_link_libraries(imgui PUBLIC glfw)

  add_executable(s3vault app/desktop/main.cpp app/ui/app.cpp app/ui/panels.cpp app/ui/preview_view.cpp app/ui/file_browser.cpp)
  target_include_directories(s3vault PRIVATE app/ui ${TP}/stb ${TP}/icons)
  target_compile_definitions(s3vault PRIVATE S3V_FONT_DIR="${CMAKE_INSTALL_PREFIX}/share/s3vault/fonts"
                             S3V_FONT_DIR_BUILD="${TP}/fonts")
  target_link_libraries(s3vault PRIVATE s3vault_core imgui glfw)
  install(TARGETS s3vault RUNTIME DESTINATION bin)
  install(FILES ${TP}/fonts/fa-solid-900.ttf ${TP}/fonts/LICENSE-fontawesome.txt DESTINATION share/s3vault/fonts)
  install(FILES s3vault.desktop DESTINATION share/applications)
endif()

install(TARGETS s3vault-cli RUNTIME DESTINATION bin)
