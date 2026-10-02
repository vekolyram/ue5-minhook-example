#pragma once
//
// PE section walking + AOB (array-of-bytes) pattern scanning.
//
// The runtime scan walks the RVA space of a loaded module; the offline scan in
// tools/aobscan.mjs walks file offsets. Both resolve to the same RVA, which is
// what makes a signature validated offline usable online.
//
// Only executable sections are searched. A function prologue never lives in
// .rdata/.data, and skipping them removes most of the image from the scan.
//
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace scan {

// ---------------------------------------------------------------------------
// Pattern
// ---------------------------------------------------------------------------

// A parsed signature: each element is a required byte (0..255) or -1 for a
// wildcard. Text form accepts "4C 8B DC ?? ??" and also "4C8BDC" runs.
class BytePattern {
public:
    bool parse(const char* text) {
        bytes_.clear();
        for (const char* p = text; *p != '\0';) {
            if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
                ++p;
                continue;
            }
            if (*p == '?') {
                bytes_.push_back(-1);
                ++p;
                if (*p == '?') ++p;  // consume the second '?' of "??"
                continue;
            }
            const int hi = hexDigit(p[0]);
            const int lo = hexDigit(p[1]);
            if (hi < 0 || lo < 0) {
                bytes_.clear();
                return false;
            }
            bytes_.push_back((hi << 4) | lo);
            p += 2;
        }
        return !bytes_.empty();
    }

    size_t size() const { return bytes_.size(); }
    int at(size_t i) const { return bytes_[i]; }

    // Index of the first fixed byte, or npos when every byte is a wildcard.
    // Scanning starts by matching this byte, which keeps the inner loop short.
    size_t firstFixed() const {
        for (size_t i = 0; i < bytes_.size(); ++i) {
            if (bytes_[i] >= 0) return i;
        }
        return bytes_.size();
    }

    size_t wildcardCount() const {
        size_t n = 0;
        for (int b : bytes_) {
            if (b < 0) ++n;
        }
        return n;
    }

private:
    static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    std::vector<int> bytes_;
};

// ---------------------------------------------------------------------------
// Module sections
// ---------------------------------------------------------------------------

struct Section {
    const uint8_t* begin = nullptr;
    size_t size = 0;
    char name[9] = {};
};

// Executable sections of the image loaded at `base`, in header order.
inline std::vector<Section> executableSections(const uint8_t* base) {
    std::vector<Section> out;
    if (base == nullptr) return out;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return out;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return out;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        // In memory the mapped size is VirtualSize; SizeOfRawData is the file
        // size and can be larger for a section whose tail is zero-filled.
        const DWORD vsize = sec->Misc.VirtualSize != 0 ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (vsize == 0) continue;

        Section s;
        s.begin = base + sec->VirtualAddress;
        s.size = vsize;
        std::memcpy(s.name, sec->Name, 8);
        s.name[8] = '\0';
        out.push_back(s);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

// Address of the first match inside [begin, end), or nullptr.
inline const uint8_t* findIn(const uint8_t* begin, const uint8_t* end, const BytePattern& p) {
    const size_t n = p.size();
    if (n == 0 || begin == nullptr || end == nullptr) return nullptr;
    if (static_cast<size_t>(end - begin) < n) return nullptr;

    const size_t anchor = p.firstFixed();
    if (anchor == n) return nullptr;  // all wildcards: nothing to anchor on
    const int anchorByte = p.at(anchor);

    const uint8_t* const last = end - n;
    for (const uint8_t* cur = begin; cur <= last; ++cur) {
        if (cur[anchor] != static_cast<uint8_t>(anchorByte)) continue;
        size_t i = 0;
        for (; i < n; ++i) {
            const int want = p.at(i);
            if (want >= 0 && cur[i] != static_cast<uint8_t>(want)) break;
        }
        if (i == n) return cur;
    }
    return nullptr;
}

struct Match {
    const uint8_t* address = nullptr;
    // Owned by value: the Section vector is a temporary inside scanModule, so a
    // pointer into Section::name would dangle the moment the loop ends.
    std::string section;
};

// Every match across the executable sections of the module at `base`.
//
// Uniqueness is the caller's business: a signature that hits twice will hook
// whichever the loader happened to place first, which is a coin flip across
// builds. `scanModuleUnique` refuses that case instead of guessing.
inline std::vector<Match> scanModule(const uint8_t* base, const BytePattern& p) {
    std::vector<Match> hits;
    for (const Section& s : executableSections(base)) {
        const uint8_t* cur = s.begin;
        const uint8_t* const end = s.begin + s.size;
        for (;;) {
            const uint8_t* hit = findIn(cur, end, p);
            if (hit == nullptr) break;
            hits.push_back(Match{hit, std::string(s.name)});
            cur = hit + 1;
        }
    }
    return hits;
}

}  // namespace scan
