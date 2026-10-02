#pragma once
//
// Linear-sweep instruction decoding, used to recover a global from a function.
//
// The column's path 1 is "find a function, then look at which global it
// references" -- functions have structure, globals are just bytes. Doing that
// at runtime needs a length disassembler. MinHook already vendors one (HDE64)
// and this project already links it, so no new dependency appears here.
//
#include <windows.h>

#include <cstdint>
#include <vector>

#include "hde64.h"

namespace disasm {

// RIP-relative memory operands in a linear sweep starting at `code`.
//
// Both forms are collected, and for both the TARGET IS THE GLOBAL'S ADDRESS:
//
//     lea reg, [rip+disp]   -> operand is the address of the global
//     mov reg, [rip+disp]   -> operand is the value, but the address is the
//                              same arithmetic
//
// Which of the two a given function uses is a compiler decision, so collecting
// both and validating the candidates beats trying to predict it.
//
// The sweep stops at the first byte HDE64 cannot decode, which in practice is
// the end of the function's contiguous instruction stream.
inline std::vector<const uint8_t*> ripRelativeTargets(const uint8_t* code, size_t maxBytes,
                                                      size_t maxInstructions = 8192) {
    std::vector<const uint8_t*> targets;
    if (code == nullptr) return targets;

    const uint8_t* cur = code;
    const uint8_t* const end = code + maxBytes;

    for (size_t n = 0; n < maxInstructions && cur < end; ++n) {
        hde64s hs{};
        const unsigned int len = hde64_disasm(cur, &hs);
        if (len == 0 || (hs.flags & F_ERROR) != 0) break;

        // mod=00, rm=101 is the RIP-relative form in 64-bit mode; HDE64 gives it
        // a 4-byte displacement (hde64.c, the `case 0: if (m_rm == 5)` branch).
        const bool ripRelative = (hs.flags & F_MODRM) != 0 && hs.modrm_mod == 0 &&
                                 hs.modrm_rm == 5 && (hs.flags & F_DISP32) != 0;
        if (ripRelative) {
            const int32_t disp = static_cast<int32_t>(hs.disp.disp32);
            targets.push_back(cur + len + disp);
        }

        cur += len;
    }
    return targets;
}

}  // namespace disasm
