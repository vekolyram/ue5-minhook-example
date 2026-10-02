// ---------------------------------------------------------------------------
// ue5hook.dll -- a UE5 MinHook example
//
// What it does: finds UObject::StaticConstructObject_Internal in the running
// game by AOB signature, inline-hooks it with MinHook, and logs every call
// (class pointer, outer, FName, flags) to a file without slowing the game down.
//
// Target: KARDS  kards-Win64-Shipping.exe  (also matches kards-Win64-Shipping1,
// dlw1 and CMTEST测卡服 -- all four builds carry the same signature at the same
// RVA, verified with tools/aobscan.mjs).
//
// Design notes, each of which is a bug avoided:
//
//   * DllMain does no real work. Under the loader lock, CreateThread is legal
//     but almost nothing else is: the CRT may not be initialised, and a
//     blocking call can deadlock the whole process. The worker thread owns
//     everything.
//
//   * The signature must match exactly once. A pattern that hits twice would
//     hook whichever copy the linker placed first -- a coin flip that changes
//     between builds. Refusing is cheaper than debugging that.
//
//   * The detour does no I/O, no locking and no allocation. It copies a POD
//     record into a lock-free ring; a consumer thread writes the file. This
//     function runs thousands of times during startup.
//
//   * Hooks are enabled through the queue API. Every MH_EnableHook suspends and
//     resumes every thread in the process; MH_QueueEnableHook + MH_ApplyQueued
//     pays that cost once no matter how many hooks you install.
//
//   * Teardown order is Disable -> Remove -> Uninitialize. Getting it wrong
//     crashes on exit, which is easily mistaken for "the hook was wrong".
//
// Build: see build.bat / CMakeLists.txt.  x64 only.
// ---------------------------------------------------------------------------

#include <windows.h>

#include <MinHook.h>
#include <intrin.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <string>
#include <vector>

#include "async_log.h"
#include "scan.h"

namespace {

// ---------------------------------------------------------------------------
// The signature
// ---------------------------------------------------------------------------

// UObject::StaticConstructObject_Internal, UE5.
//
//   4C 8B DC              mov  r11, rsp
//   55                    push rbp
//   53                    push rbx
//   41 56                 push r14
//   49 8D AB 28 FE FF FF  lea  rbp, [r11-1D8h]
//   48 81 EC C0 02 00 00  sub  rsp, 2C0h
//   48 8B 05 ?? ?? ?? ??  mov  rax, [rip+disp]     <- __security_cookie, the wildcard
//   48 33 C4              xor  rax, rsp
//   48 89 85 A0 01 00 00  mov  [rbp+1A0h], rax
//   8B 41 70              mov  eax, [rcx+70h]      <- rcx is &FStaticConstructObjectParameters
//   33 DB                 xor  ebx, ebx
//   49 89 73 10           mov  [r11+10h], rsi
//
// The only varying bytes are the security-cookie displacement, which is a
// RIP-relative address and therefore moves with any relink. The 4 wildcards
// cover exactly those bytes and nothing else.
//
// Verified: 1 hit in .text, RVA 0x015C6C80, preceded by 8 bytes of int3 padding
// (CC CC CC CC CC CC CC CC) -- the shape of a real function entry.
constexpr const char* kSignature =
    "4C 8B DC 55 53 41 56 49 8D AB 28 FE FF FF 48 81 EC C0 02 00 00 "
    "48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 A0 01 00 00 8B 41 70 33 DB 49 89 73 10";

// Fallback: the same function, anchored 14 bytes past the entry.
//
// UE4SS is installed in this game and hooks this very function (its
// "Waiting for object construction..." line is that hook). Its x64 hook writes
// a 14-byte absolute jump over the prologue, which DESTROYS the primary
// signature -- measured: injecting at 0.55s finds it, injecting at 30s reports
// "not found" while the function is still right there.
//
// This signature starts after that jump, so it survives, and the entry is
// recovered by subtracting the displacement. Verified unique in all four
// builds at RVA 0x015C6C8E == 0x015C6C80 + 14.
//
// The trade-off is honest: this anchors on the body, so a tool that hooks
// deeper into the function defeats it too. Two signatures cover the realistic
// cases; a third would be guesswork.
constexpr const char* kFallbackSignature =
    "48 81 EC C0 02 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 A0 01 00 00 "
    "8B 41 70 33 DB 49 89 73 10";
constexpr uintptr_t kFallbackDisplacement = 14;

// Offsets into FStaticConstructObjectParameters. The engine's own prologue
// proves 0x70 exists; 0x00/0x08/0x10 follow the struct's declared field order
// (Class, Outer, Name) and should be re-confirmed against your SDK dump before
// you rely on them for anything beyond correlation.
constexpr size_t kOffClass = 0x00;
constexpr size_t kOffOuter = 0x08;
constexpr size_t kOffName = 0x10;
constexpr size_t kOffFlags70 = 0x70;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

using StaticConstructObjectFn = void*(__fastcall*)(void* params);

StaticConstructObjectFn g_original = nullptr;
void* g_target = nullptr;  // the resolved function address, needed for removal
asynclog::Ring g_log;
std::atomic<uint64_t> g_calls{0};
std::atomic<uint64_t> g_logged{0};
std::atomic<uint64_t> g_limit{0};  // 0 = unlimited
HMODULE g_self = nullptr;

// ---------------------------------------------------------------------------
// The detour
// ---------------------------------------------------------------------------

void* __fastcall DetourStaticConstructObject(void* params) {
    // Call through first so the record can carry the result. The engine can
    // recurse into this function, which is fine: the ring is MPMC.
    void* result = g_original(params);

    const uint64_t n = g_calls.fetch_add(1, std::memory_order_relaxed) + 1;
    const uint64_t limit = g_limit.load(std::memory_order_relaxed);
    if (limit != 0 && n > limit) return result;

    asynclog::Record r;
    r.seq = n;
    r.threadId = GetCurrentThreadId();
    r.params = params;
    r.result = result;
    r.retAddr = _ReturnAddress();
    if (params != nullptr) {
        r.cls = *reinterpret_cast<void* const*>(static_cast<const uint8_t*>(params) + kOffClass);
        r.outer = *reinterpret_cast<void* const*>(static_cast<const uint8_t*>(params) + kOffOuter);
        std::memcpy(&r.name, static_cast<const uint8_t*>(params) + kOffName, sizeof(r.name));
        std::memcpy(&r.flags70, static_cast<const uint8_t*>(params) + kOffFlags70,
                    sizeof(r.flags70));
    }
    g_log.push(r);
    g_logged.fetch_add(1, std::memory_order_relaxed);
    return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

void DebugPrint(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, args);
    va_end(args);
    OutputDebugStringW(buf);
}

std::wstring ReadEnv(const wchar_t* name, const std::wstring& fallback) {
    wchar_t buf[1024];
    const DWORD n = GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n >= std::size(buf)) return fallback;
    return std::wstring(buf, n);
}

std::wstring DirectoryOf(HMODULE module) {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(module, path, MAX_PATH);
    std::wstring s(path);
    const size_t slash = s.find_last_of(L"\\/");
    return slash == std::wstring::npos ? s : s.substr(0, slash);
}

// Failure breadcrumb.
//
// Every early return happens before the async logger exists, so without this
// an injected DLL that decides not to hook anything leaves no trace at all --
// indistinguishable from "the injector silently failed". Appending directly is
// safe here precisely because no consumer thread is running yet.
void Fail(const std::wstring& logPath, const std::wstring& message) {
    DebugPrint(L"[ue5hook] %s\n", message.c_str());
    std::FILE* f = nullptr;
    if (_wfopen_s(&f, logPath.c_str(), L"a, ccs=UTF-8") == 0 && f != nullptr) {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        std::fwprintf(f, L"# ue5hook FAILED %04u-%02u-%02u %02u:%02u:%02u  %s\n", st.wYear,
                      st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, message.c_str());
        std::fclose(f);
    }
}

// The module we scan. Defaults to the process image, which is right for the
// proxy-DLL and injector cases; override with UE5HOOK_MODULE when the target
// lives in a different DLL.
HMODULE ResolveTargetModule(std::wstring& nameOut) {
    const std::wstring configured = ReadEnv(L"UE5HOOK_MODULE", L"");
    if (!configured.empty()) {
        nameOut = configured;
        return GetModuleHandleW(configured.c_str());
    }
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    nameOut = path;
    return GetModuleHandleW(nullptr);
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

DWORD WINAPI Worker(LPVOID) {
    // Resolved first so every early return below can leave a breadcrumb.
    const std::wstring logPath = ReadEnv(L"UE5HOOK_LOG", DirectoryOf(g_self) + L"\\ue5hook.log");

    std::wstring moduleName;
    HMODULE module = ResolveTargetModule(moduleName);
    if (module == nullptr) {
        Fail(logPath, L"target module not loaded: " + moduleName);
        return 1;
    }

    const auto base = reinterpret_cast<const uint8_t*>(module);

    // ---- locate -----------------------------------------------------------
    scan::BytePattern pattern;
    if (!pattern.parse(kSignature)) {
        Fail(logPath, L"signature failed to parse");
        return 1;
    }

    void* target = nullptr;
    std::string section;
    const wchar_t* which = L"primary";

    std::vector<scan::Match> hits = scan::scanModule(base, pattern);
    if (hits.size() > 1) {
        wchar_t buf[160];
        _snwprintf_s(buf, _TRUNCATE, L"signature is not unique (%zu hits); refusing to guess",
                     hits.size());
        Fail(logPath, buf);
        return 1;
    }

    if (hits.size() == 1) {
        target = const_cast<uint8_t*>(hits[0].address);
        section = hits[0].section;
    } else {
        // Primary is gone. The overwhelmingly likely reason in this game is
        // UE4SS having hooked the entry already, so try the displaced form.
        scan::BytePattern fallback;
        if (!fallback.parse(kFallbackSignature)) {
            Fail(logPath, L"fallback signature failed to parse");
            return 1;
        }
        std::vector<scan::Match> displaced = scan::scanModule(base, fallback);
        if (displaced.size() > 1) {
            wchar_t buf[160];
            _snwprintf_s(buf, _TRUNCATE,
                         L"fallback signature is not unique (%zu hits); refusing to guess",
                         displaced.size());
            Fail(logPath, buf);
            return 1;
        }
        if (displaced.empty()) {
            Fail(logPath,
                 L"signature not found in " + moduleName +
                     L" -- neither the entry nor the displaced form. Another tool may have "
                     L"hooked deeper into the function, or this is a different build");
            return 1;
        }
        target = const_cast<uint8_t*>(displaced[0].address) - kFallbackDisplacement;
        section = displaced[0].section;
        which = L"fallback (entry overwritten by another hook)";
    }

    g_target = target;
    const uintptr_t rva = reinterpret_cast<uintptr_t>(target) - reinterpret_cast<uintptr_t>(base);

    // ---- logging ----------------------------------------------------------
    wchar_t header[512];
    // %hs, not %s: in a wide printf %s means wchar_t*, and section is a
    // std::string. Passing it to %s reads ".text" as UTF-16 -- 0x742E, 0x7865,
    // 0x0074 -- and prints "琮硥t".
    _snwprintf_s(header, _TRUNCATE,
                 L"# ue5hook  module=%s  RVA=0x%llX  section=%hs  via=%s", moduleName.c_str(),
                 static_cast<unsigned long long>(rva), section.c_str(), which);
    if (!g_log.start(logPath.c_str(), 1u << 16, header)) {
        Fail(logPath, L"cannot open log");
        return 1;
    }
    {
        wchar_t limitBuf[64] = {};
        GetEnvironmentVariableW(L"UE5HOOK_LIMIT", limitBuf, 64);
        g_limit.store(_wcstoui64(limitBuf, nullptr, 10), std::memory_order_relaxed);
    }

    // ---- hook -------------------------------------------------------------
    const MH_STATUS initStatus = MH_Initialize();
    if (initStatus != MH_OK && initStatus != MH_ERROR_ALREADY_INITIALIZED) {
        wchar_t buf[128];
        _snwprintf_s(buf, _TRUNCATE, L"MH_Initialize failed: %d", static_cast<int>(initStatus));
        Fail(logPath, buf);
        g_log.stop();
        return 1;
    }

    const MH_STATUS createStatus =
        MH_CreateHook(target, reinterpret_cast<LPVOID>(&DetourStaticConstructObject),
                      reinterpret_cast<LPVOID*>(&g_original));
    if (createStatus != MH_OK) {
        wchar_t buf[128];
        _snwprintf_s(buf, _TRUNCATE, L"MH_CreateHook failed: %d", static_cast<int>(createStatus));
        Fail(logPath, buf);
        MH_Uninitialize();
        g_log.stop();
        return 1;
    }

    // One global thread suspension for the whole batch, not one per hook.
    MH_QueueEnableHook(target);
    const MH_STATUS applyStatus = MH_ApplyQueued();
    if (applyStatus != MH_OK) {
        wchar_t buf[128];
        _snwprintf_s(buf, _TRUNCATE, L"MH_ApplyQueued failed: %d", static_cast<int>(applyStatus));
        Fail(logPath, buf);
        MH_RemoveHook(target);
        MH_Uninitialize();
        g_log.stop();
        return 1;
    }

    DebugPrint(L"[ue5hook] hooked %s+0x%llX (section %hs, via %s), log %s\n", moduleName.c_str(),
               static_cast<unsigned long long>(rva), section.c_str(), which, logPath.c_str());

    // Stay resident until the process exits or the DLL is freed. The call
    // budget is enforced in the detour, so there is nothing to poll for here.
    for (;;) Sleep(1000);
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

// Called from DllMain on FreeLibrary only. Never on process termination: by
// then the CRT is being torn down and stopping threads from under the loader
// lock is how you get an exit-time hang.
//
// MH_RemoveHook takes a TARGET ADDRESS, not MH_ALL_HOOKS. MH_EnableHook and
// MH_DisableHook special-case MH_ALL_HOOKS; MH_RemoveHook does not -- it calls
// FindHookEntry(pTarget), which compares pTarget against each hook's target.
// MH_ALL_HOOKS is NULL, so it searches for a hook whose target is NULL, finds
// none, and returns MH_ERROR_NOT_CREATED. It is a silent no-op, and it is what
// the usual "Disable/Remove/Uninitialize with MH_ALL_HOOKS" snippet does.
// Passing the real address is the only form that removes anything.
void Teardown() {
    if (g_target != nullptr) {
        MH_DisableHook(g_target);
        MH_RemoveHook(g_target);
    }
    MH_Uninitialize();
    g_log.stop();
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH: {
            g_self = self;
            DisableThreadLibraryCalls(self);
            // Nothing but a thread start: see the header comment.
            HANDLE t = CreateThread(nullptr, 0, &Worker, nullptr, 0, nullptr);
            if (t != nullptr) CloseHandle(t);
            return TRUE;
        }
        case DLL_PROCESS_DETACH:
            // reserved != nullptr means the process is exiting, not FreeLibrary.
            if (reserved == nullptr) Teardown();
            return TRUE;
        default:
            return TRUE;
    }
}
