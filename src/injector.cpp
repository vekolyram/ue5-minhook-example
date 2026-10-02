// ---------------------------------------------------------------------------
// injector.exe -- minimal remote LoadLibrary / FreeLibrary driver
//
//   injector.exe <process-name-or-pid> <dll-path>            inject
//   injector.exe <process-name-or-pid> <dll-name> --eject    eject by module name
//
// This is a plain CreateRemoteThread + LoadLibraryW injector. It is the least
// interesting part of the project and it is deliberately boring: it exists so
// the example is self-contained, not because it is a good way to get a DLL into
// a game. Prefer the proxy-DLL route (see README) when you want the hook to be
// present from process start, before the engine constructs its first object.
//
// Anything that loads a DLL into a process it does not own will be flagged by
// anti-cheat and by some AV products. Use it on your own builds.
// ---------------------------------------------------------------------------

#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

DWORD FindProcessIdByName(const wchar_t* name) {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD found = 0;
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name) == 0) {
                found = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

// Address of a module inside the target. Needs PROCESS_QUERY_INFORMATION |
// PROCESS_VM_READ on the handle.
HMODULE RemoteModuleBase(DWORD pid, const wchar_t* moduleName) {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    HMODULE found = nullptr;
    if (Module32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, moduleName) == 0) {
                found = entry.hModule;
                break;
            }
        } while (Module32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

// Run `proc` in the target with one pointer-sized argument.
bool RemoteCall(HANDLE process, void* proc, void* arg, DWORD* resultOut) {
    // The string must live in the target's address space.
    const SIZE_T bytes = arg != nullptr ? wcslen(static_cast<const wchar_t*>(arg)) * sizeof(wchar_t) +
                                              sizeof(wchar_t)
                                        : 0;
    void* remoteArg = nullptr;
    if (bytes != 0) {
        remoteArg = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
        if (remoteArg == nullptr) {
            std::fwprintf(stderr, L"VirtualAllocEx failed: %lu\n", GetLastError());
            return false;
        }
        if (!WriteProcessMemory(process, remoteArg, arg, bytes, nullptr)) {
            std::fwprintf(stderr, L"WriteProcessMemory failed: %lu\n", GetLastError());
            VirtualFreeEx(process, remoteArg, 0, MEM_RELEASE);
            return false;
        }
    }

    const HANDLE thread =
        CreateRemoteThread(process, nullptr, 0,
                           reinterpret_cast<LPTHREAD_START_ROUTINE>(proc), remoteArg, 0, nullptr);
    if (thread == nullptr) {
        std::fwprintf(stderr, L"CreateRemoteThread failed: %lu\n", GetLastError());
        if (remoteArg != nullptr) VirtualFreeEx(process, remoteArg, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread, 15000);
    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);
    if (remoteArg != nullptr) VirtualFreeEx(process, remoteArg, 0, MEM_RELEASE);

    if (resultOut != nullptr) *resultOut = exitCode;
    return true;
}

void Usage() {
    std::fwprintf(stderr,
                  L"usage:\n"
                  L"  injector.exe <process-name-or-pid> <dll-path>\n"
                  L"  injector.exe <process-name-or-pid> <dll-name> --eject\n");
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        Usage();
        return 2;
    }

    const bool eject = (argc >= 4 && _wcsicmp(argv[3], L"--eject") == 0);

    // Accept either a pid or an image name.
    DWORD pid = wcstoul(argv[1], nullptr, 10);
    if (pid == 0) pid = FindProcessIdByName(argv[1]);
    if (pid == 0) {
        std::fwprintf(stderr, L"process not found: %s\n", argv[1]);
        return 1;
    }

    const DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                         PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    const HANDLE process = OpenProcess(access, FALSE, pid);
    if (process == nullptr) {
        std::fwprintf(stderr, L"OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return 1;
    }

    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    bool ok = false;

    if (eject) {
        HMODULE base = RemoteModuleBase(pid, argv[2]);
        if (base == nullptr) {
            std::fwprintf(stderr, L"module not loaded in target: %s\n", argv[2]);
            CloseHandle(process);
            return 1;
        }
        auto freeLibrary = reinterpret_cast<void*>(GetProcAddress(kernel32, "FreeLibrary"));
        DWORD result = 0;
        ok = RemoteCall(process, freeLibrary, base, &result) && result != 0;
        std::wprintf(L"%s: %s\n", ok ? L"ejected" : L"eject failed", argv[2]);
    } else {
        // LoadLibraryW wants a full path; the target's CWD is not ours.
        wchar_t full[MAX_PATH] = {};
        if (GetFullPathNameW(argv[2], MAX_PATH, full, nullptr) == 0) {
            std::fwprintf(stderr, L"cannot resolve path: %s\n", argv[2]);
            CloseHandle(process);
            return 1;
        }
        auto loadLibrary = reinterpret_cast<void*>(GetProcAddress(kernel32, "LoadLibraryW"));
        DWORD result = 0;
        ok = RemoteCall(process, loadLibrary, full, &result) && result != 0;
        if (ok) {
            std::wprintf(L"injected into pid %lu: %s\n", pid, full);
        } else {
            std::fwprintf(stderr,
                          L"injection failed (LoadLibraryW returned 0). "
                          L"Check the target's bitness and that the path exists.\n");
        }
    }

    CloseHandle(process);
    return ok ? 0 : 1;
}
