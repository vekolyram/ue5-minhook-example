// ---------------------------------------------------------------------------
// selftest.exe -- evidence that the example's two load-bearing claims hold.
//
//   node tools/aobscan.mjs  proves the signature matches the file on disk.
//   this program            proves the C++ scanner the DLL actually ships
//                           reaches the same answer, and that the MinHook
//                           round-trip works with the detour shape used by
//                           dllmain.cpp.
//
// What this CANNOT prove, and does not claim to: that RCX really is
// &FStaticConstructObjectParameters at runtime, or that the field offsets
// 0x00/0x08/0x10/0x70 are what dllmain.cpp says. Those need a live run against
// the game. See README.md.
//
//   selftest.exe [path-to-kards-Win64-Shipping.exe]
// ---------------------------------------------------------------------------

#include <windows.h>

#include <MinHook.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "scan.h"

namespace {

// Same signature and same expected landing spot as src/dllmain.cpp.
constexpr const char* kSignature =
    "4C 8B DC 55 53 41 56 49 8D AB 28 FE FF FF 48 81 EC C0 02 00 00 "
    "48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 A0 01 00 00 8B 41 70 33 DB 49 89 73 10";

// Established independently by tools/aobscan.mjs, which resolves file offsets
// through the section table.
constexpr uintptr_t kExpectedRva = 0x015C6C80;

// Same displaced fallback as src/dllmain.cpp.
constexpr const char* kFallbackSignature =
    "48 81 EC C0 02 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 A0 01 00 00 "
    "8B 41 70 33 DB 49 89 73 10";
constexpr uintptr_t kFallbackDisplacement = 14;

int g_failures = 0;

void Check(bool ok, const char* what) {
    std::printf("%s  %s\n", ok ? "[ok]  " : "[FAIL]", what);
    if (!ok) ++g_failures;
}

// ---------------------------------------------------------------------------
// Map a PE image into memory the way the loader would, without running it.
//
// LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) is unreliable for .exe images, so
// this copies the headers and each section to its virtual address by hand. The
// result is byte-identical to what scanModule would see inside the game, which
// is the whole point: it exercises the shipped scanner, not a reimplementation.
// ---------------------------------------------------------------------------
struct MappedImage {
    std::vector<uint8_t> storage;
    const uint8_t* base() const { return storage.data(); }
    size_t size() const { return storage.size(); }
};

bool MapImage(const wchar_t* path, MappedImage& out) {
    const HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        std::printf("      CreateFileW failed: %lu\n", GetLastError());
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0) {
        CloseHandle(file);
        return false;
    }

    std::vector<uint8_t> raw(static_cast<size_t>(fileSize.QuadPart));
    DWORD got = 0;
    const BOOL readOk = ReadFile(file, raw.data(), static_cast<DWORD>(raw.size()), &got, nullptr);
    CloseHandle(file);
    if (!readOk || got != raw.size()) {
        std::printf("      ReadFile failed: %lu\n", GetLastError());
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const size_t imageSize = nt->OptionalHeader.SizeOfImage;
    out.storage.assign(imageSize, 0);

    const size_t headerBytes =
        std::min<size_t>(nt->OptionalHeader.SizeOfHeaders, imageSize);
    std::memcpy(out.storage.data(), raw.data(), headerBytes);

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        const size_t dst = sec->VirtualAddress;
        if (dst >= imageSize || sec->SizeOfRawData == 0) continue;
        if (sec->PointerToRawData >= raw.size()) continue;
        const size_t n = std::min<size_t>(
            {static_cast<size_t>(sec->SizeOfRawData), imageSize - dst,
             raw.size() - sec->PointerToRawData});
        std::memcpy(out.storage.data() + dst, raw.data() + sec->PointerToRawData, n);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Test 1: the scanner lands where the offline scan says it should.
// ---------------------------------------------------------------------------
void TestSignature(const wchar_t* gamePath) {
    std::printf("\n== signature vs %ls ==\n", gamePath);

    MappedImage image;
    if (!MapImage(gamePath, image)) {
        Check(false, "map the game image");
        return;
    }
    std::printf("      mapped %zu bytes\n", image.size());

    scan::BytePattern pattern;
    Check(pattern.parse(kSignature), "pattern parses");
    std::printf("      %zu bytes, %zu wildcards\n", pattern.size(), pattern.wildcardCount());

    const std::vector<scan::Match> hits = scan::scanModule(image.base(), pattern);
    std::printf("      hits: %zu\n", hits.size());
    for (const scan::Match& m : hits) {
        std::printf("        %s RVA=0x%08llX\n", m.section.c_str(),
                    static_cast<unsigned long long>(m.address - image.base()));
    }

    Check(hits.size() == 1, "signature is unique in the image");
    if (hits.size() != 1) return;

    const uintptr_t rva = reinterpret_cast<uintptr_t>(hits[0].address) -
                          reinterpret_cast<uintptr_t>(image.base());
    Check(rva == kExpectedRva, "RVA matches the offline scan (0x015C6C80)");
    Check(hits[0].section == ".text", "landed in .text");

    // A real function entry is padded with int3; a hit in the middle of another
    // function would not be. This is the cheapest independent confirmation that
    // the signature names a prologue and not an arbitrary byte run.
    bool padded = true;
    for (int i = 1; i <= 8; ++i) {
        if (hits[0].address[-i] != 0xCC) {
            padded = false;
            break;
        }
    }
    Check(padded, "preceded by 8 bytes of int3 padding (looks like a function entry)");

    // The displaced fallback must land exactly kFallbackDisplacement bytes past
    // the entry, so subtracting recovers the same address. This is what lets a
    // late injection still work after UE4SS has overwritten the prologue.
    scan::BytePattern fallback;
    Check(fallback.parse(kFallbackSignature), "fallback pattern parses");
    const std::vector<scan::Match> displaced = scan::scanModule(image.base(), fallback);
    Check(displaced.size() == 1, "fallback signature is unique in the image");
    if (displaced.size() == 1) {
        const uintptr_t displacedRva = reinterpret_cast<uintptr_t>(displaced[0].address) -
                                       reinterpret_cast<uintptr_t>(image.base());
        Check(displacedRva == kExpectedRva + kFallbackDisplacement,
              "fallback RVA is exactly 14 past the entry (0x015C6C8E)");
        Check(displacedRva - kFallbackDisplacement == kExpectedRva,
              "subtracting the displacement recovers the entry");
    }
}

// ---------------------------------------------------------------------------
// Test 2: MinHook install -> detour fires -> original still reachable -> remove.
//
// The target is a synthetic function in RWX memory rather than a game address:
// the point is to exercise the MinHook calls and the detour shape, not to
// pretend this validates the game's ABI.
// ---------------------------------------------------------------------------
using SyntheticFn = int(__fastcall*)();

SyntheticFn g_original = nullptr;
int g_detourCalls = 0;

int __fastcall DetourSynthetic() {
    ++g_detourCalls;
    return g_original() + 100;  // must call through, same as the real detour
}

void TestMinHook() {
    std::printf("\n== MinHook round-trip ==\n");

    // mov eax, 42 ; ret   ->  B8 2A 00 00 00 C3
    const uint8_t code[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
    void* target = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (target == nullptr) {
        Check(false, "VirtualAlloc an executable stub");
        return;
    }
    std::memcpy(target, code, sizeof(code));

    auto call = reinterpret_cast<SyntheticFn>(target);
    Check(call() == 42, "stub returns 42 before hooking");

    const MH_STATUS initStatus = MH_Initialize();
    Check(initStatus == MH_OK || initStatus == MH_ERROR_ALREADY_INITIALIZED, "MH_Initialize");

    const MH_STATUS createStatus = MH_CreateHook(target, reinterpret_cast<LPVOID>(&DetourSynthetic),
                                                 reinterpret_cast<LPVOID*>(&g_original));
    Check(createStatus == MH_OK, "MH_CreateHook");
    if (createStatus != MH_OK) {
        VirtualFree(target, 0, MEM_RELEASE);
        return;
    }

    // The queue API is what dllmain.cpp uses; exercising it here keeps the test
    // honest about the path that actually runs in the game.
    MH_QueueEnableHook(target);
    Check(MH_ApplyQueued() == MH_OK, "MH_QueueEnableHook + MH_ApplyQueued");

    const int hooked = call();
    Check(hooked == 142, "detour fired and chained to the original (42 + 100)");
    Check(g_detourCalls == 1, "detour ran exactly once");

    Check(MH_DisableHook(MH_ALL_HOOKS) == MH_OK, "MH_DisableHook(MH_ALL_HOOKS)");
    Check(call() == 42, "stub returns 42 again after unhooking");
    Check(g_detourCalls == 1, "detour did not run while disabled");

    // MH_ALL_HOOKS is NOT valid here. MH_RemoveHook calls FindHookEntry, which
    // compares the argument against each hook's target; MH_ALL_HOOKS is NULL,
    // so the lookup misses and the call returns MH_ERROR_NOT_CREATED without
    // removing anything. Assert that behaviour explicitly so the trap cannot
    // come back unnoticed, then remove by the real address.
    Check(MH_RemoveHook(MH_ALL_HOOKS) == MH_ERROR_NOT_CREATED,
          "MH_RemoveHook(MH_ALL_HOOKS) is a no-op returning MH_ERROR_NOT_CREATED");
    Check(MH_RemoveHook(target) == MH_OK, "MH_RemoveHook(target)");
    Check(MH_Uninitialize() == MH_OK, "MH_Uninitialize");

    VirtualFree(target, 0, MEM_RELEASE);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    // No hardcoded path: this repository does not know where anyone keeps their
    // game. Pass a binary, set the env var, or run the MinHook half alone.
    const wchar_t* gamePath = argc >= 2 ? argv[1] : _wgetenv(L"UE5HOOK_TEST_BINARY");

    std::printf("ue5hook selftest\n");

    if (gamePath != nullptr && gamePath[0] != L'\0') {
        TestSignature(gamePath);
    } else {
        std::printf("\n== signature test SKIPPED ==\n");
        std::printf("      no binary given. The signature half of this test needs a UE5\n");
        std::printf("      shipping binary to scan:\n\n");
        std::printf("        selftest.exe <path-to-binary>\n");
        std::printf("        set UE5HOOK_TEST_BINARY=<path>\n\n");
        std::printf("      The binary is mapped and scanned, never executed.\n");
    }

    TestMinHook();

    std::printf("\n%s (%d failure%s)\n", g_failures == 0 ? "ALL PASSED" : "FAILED", g_failures,
                g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
