cmake_minimum_required(VERSION 3.16)
project(s3vault CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(TP ${CMAKE_SOURCE_DIR}/third_party)
# Install layout: FHS on Linux; a flat folder on Windows (exe + DLLs + fonts/).
if(WIN32)
  set(S3V_BIN_DIR .)
  set(S3V_FONT_INSTALL fonts)
else()
  set(S3V_BIN_DIR bin)
  set(S3V_FONT_INSTALL share/s3vault/fonts)
endif()
option(S3VAULT_GUI "Build the desktop GUI (ImGui + GLFW)" ON)

# Platform backend: Linux and Windows are implemented; the others are reserved (see platform/*/README.md).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(S3V_PLATFORM linux)
  set(S3V_PLATFORM_SRC platform/linux/keychain_libsecret.cpp platform/linux/session_tmp.cpp
      platform/linux/desktop.cpp platform/linux/inotify_watcher.cpp)
elseif(WIN32)
  set(S3V_PLATFORM windows)
  set(S3V_PLATFORM_SRC platform/windows/keychain_wincred.cpp platform/windows/session_tmp.cpp
      platform/windows/desktop.cpp platform/windows/fs_watcher_win.cpp core/util/subprocess_win.cpp core/util/compat_win.cpp)
  set(S3V_MANIFEST ${CMAKE_SOURCE_DIR}/platform/windows/s3vault.rc)
  # One self-contained .exe per program: no libstdc++/libgcc/winpthread DLLs to ship.
  add_compile_definitions(_WIN32_WINNT=0x0A00 WINVER=0x0A00 UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
  add_link_options(-static -static-libgcc -static-libstdc++)
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
  ${S3V_PLATFORM_SRC})
target_include_directories(s3vault_core PUBLIC core core/include platform/iface ${TP}/curl/include)
target_link_libraries(s3vault_core PUBLIC sqlite3 pugixml ${CMAKE_DL_LIBS} pthread)
if(WIN32)
  target_link_libraries(s3vault_core PUBLIC bcrypt advapi32 shell32 ole32 uuid)
endif()
target_compile_options(s3vault_core PRIVATE -Wall -Wextra -Wno-unused-parameter)

# ---- CLI ----
add_executable(s3vault-cli cli/main.cpp ${S3V_MANIFEST})
target_link_libraries(s3vault-cli PRIVATE s3vault_core)

# ---- tests ----
add_executable(s3vault-tests tests/unit_tests.cpp ${S3V_MANIFEST})
target_link_libraries(s3vault-tests PRIVATE s3vault_core)
add_executable(s3vault-it-helper tests/it_helper.cpp ${S3V_MANIFEST})
target_link_libraries(s3vault-it-helper PRIVATE s3vault_core)

# ---- desktop GUI ----
if(S3VAULT_GUI)
  if(NOT WIN32 AND EXISTS ${TP}/sysroot/usr/include/X11/Xlib.h)
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
  if(NOT WIN32 AND EXISTS ${TP}/sysroot/usr/include/X11/Xlib.h)
    target_include_directories(glfw PRIVATE ${TP}/sysroot/usr/include)
  endif()

  set(IMGUI ${TP}/imgui)
  add_library(imgui STATIC
    ${IMGUI}/imgui.cpp ${IMGUI}/imgui_draw.cpp ${IMGUI}/imgui_tables.cpp ${IMGUI}/imgui_widgets.cpp
    ${IMGUI}/backends/imgui_impl_glfw.cpp ${IMGUI}/backends/imgui_impl_opengl3.cpp ${IMGUI}/misc/cpp/imgui_stdlib.cpp)
  target_include_directories(imgui PUBLIC ${IMGUI})
  target_link_libraries(imgui PUBLIC glfw)

  add_executable(s3vault app/desktop/main.cpp app/ui/app.cpp app/ui/theme.cpp app/ui/screens.cpp app/ui/files_view.cpp
  app/ui/views.cpp app/ui/settings_view.cpp app/ui/dialogs.cpp app/ui/ops.cpp app/ui/preview_view.cpp app/ui/file_browser.cpp
  app/ui/editor_view.cpp app/ui/i18n.cpp app/ui/motion.cpp app/ui/window_chrome.cpp app/ui/palette.cpp app/ui/shell.cpp ${S3V_MANIFEST})
  if(WIN32)
    set_target_properties(s3vault PROPERTIES WIN32_EXECUTABLE ON)  # no console window behind the GUI
    target_link_libraries(s3vault PRIVATE opengl32)
  endif()
  target_include_directories(s3vault PRIVATE app/ui ${TP}/stb ${TP}/icons)
  target_compile_definitions(s3vault PRIVATE S3V_FONT_DIR="${CMAKE_INSTALL_PREFIX}/share/s3vault/fonts"
                             S3V_FONT_DIR_BUILD="${TP}/fonts")
  target_link_libraries(s3vault PRIVATE s3vault_core imgui glfw)
  install(TARGETS s3vault RUNTIME DESTINATION ${S3V_BIN_DIR})
  install(FILES ${TP}/fonts/fa-solid-900.ttf ${TP}/fonts/LICENSE-fontawesome.txt DESTINATION ${S3V_FONT_INSTALL})
  if(NOT WIN32)
    install(FILES s3vault.desktop DESTINATION share/applications)
    install(FILES assets/s3vault.svg DESTINATION share/icons/hicolor/scalable/apps)
  endif()
endif()

install(TARGETS s3vault-cli RUNTIME DESTINATION ${S3V_BIN_DIR})
