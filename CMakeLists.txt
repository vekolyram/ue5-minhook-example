cmake_minimum_required(VERSION 3.20)
project(ue5_minhook_example LANGUAGES C CXX)

# MinHook and this example are both 64-bit only. UE5 shipping builds are x64.
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "x64 only (got ${CMAKE_SIZEOF_VOID_P}-byte pointers)")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# ---------------------------------------------------------------------------
# MinHook (vendored clone, built from source -- no package manager involved)
# ---------------------------------------------------------------------------
set(MH_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook")
if(NOT EXISTS "${MH_ROOT}/include/MinHook.h")
  message(FATAL_ERROR
    "MinHook not found at ${MH_ROOT}\n"
    "Run: git clone --depth 1 https://github.com/TsudaKageyu/minhook.git third_party/minhook")
endif()

add_library(minhook STATIC
  "${MH_ROOT}/src/hook.c"
  "${MH_ROOT}/src/buffer.c"
  "${MH_ROOT}/src/trampoline.c"
  "${MH_ROOT}/src/hde/hde32.c"
  "${MH_ROOT}/src/hde/hde64.c"
)
target_include_directories(minhook PUBLIC "${MH_ROOT}/include" PRIVATE "${MH_ROOT}/src")
target_compile_definitions(minhook PRIVATE _CRT_SECURE_NO_WARNINGS)

# ---------------------------------------------------------------------------
# The hook DLL
# ---------------------------------------------------------------------------
add_library(ue5hook SHARED src/dllmain.cpp)
target_include_directories(ue5hook PRIVATE src)
target_link_libraries(ue5hook PRIVATE minhook)

# Sources are UTF-8; without this MSVC reads them in the system code page (936
# here) and warns C4819 on every CJK character in a comment.
target_compile_options(ue5hook PRIVATE /utf-8)

# Static CRT on purpose. An injected DLL should not add a dependency on a
# particular vcruntime140.dll being present in the game's directory; the game
# ships its own and a mismatch is an avoidable class of startup failure.
set_property(TARGET ue5hook PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
set_property(TARGET minhook PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

# ---------------------------------------------------------------------------
# The injector
# ---------------------------------------------------------------------------
add_executable(injector src/injector.cpp)
target_compile_options(injector PRIVATE /utf-8)

# ---------------------------------------------------------------------------
# Self-test
#
# Compiling is not evidence that a hook is correct. This target checks the two
# claims the example rests on: that the signature locates the right RVA in the
# real binary, and that the MinHook install/call/remove round-trip works with
# the detour shape used above.
# ---------------------------------------------------------------------------
add_executable(selftest tests/selftest.cpp)
target_include_directories(selftest PRIVATE src)
target_link_libraries(selftest PRIVATE minhook)
target_compile_options(selftest PRIVATE /utf-8)
set_property(TARGET selftest PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

# ---------------------------------------------------------------------------
# Output layout: everything lands in build\bin so the two artefacts sit
# together and the DLL is easy to copy next to the game exe.
# ---------------------------------------------------------------------------
set_target_properties(ue5hook injector selftest PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
