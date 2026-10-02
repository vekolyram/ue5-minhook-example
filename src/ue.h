#pragma once
//
// UE5 anchors: GUObjectArray, the FName pool, and the object introspection that
// turns the hook's raw pointers into readable names.
//
// Everything here is DISCOVERED at runtime and VALIDATED before use. The column
// is explicit that these layouts move around -- FUObjectArray alone has four
// documented variants, and the FName entry header depends on whether the build
// has case-preserving names -- so a hardcoded offset is a bug waiting for the
// next patch:
//
//   FUObjectArray   default UE4.21-5.7 is 0x10/0x20/0x24/0x28/0x2C, but the
//                   UE5.8 dev build, Back4Blood and Multiversus all differ
//   FNameEntry      header is (bIsWide:1, Len:15) with case preservation and
//                   (bIsWide:1, ProbeHashBits:5, Len:10) without
//   FNameEntryAllocator  where Blocks sits depends on FRWLock's size
//
// So the approach is: propose candidates structurally, then accept one only if
// it passes a check that a wrong candidate cannot pass.
//
//   GUObjectArray -> the element/chunk counts must be mutually consistent, and
//                    the first chunk must hold a readable object
//   name pool     -> entry 0 must decode to exactly "None", which is
//                    NAME_None's well-known invariant in every UE build
//
#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "disasm.h"
#include "scan.h"

namespace ue {

// ---------------------------------------------------------------------------
// Guarded reads
// ---------------------------------------------------------------------------

// Committed, readable region of this process's address space.
struct Region {
    uintptr_t begin;
    uintptr_t end;
};

// Snapshot of every readable region, taken once before discovery.
//
// readable() started out calling VirtualQuery per access. On this target that
// costs roughly 65 microseconds -- 94 threads and a large VAD tree -- and a
// 96,000-object walk needs about six checks per object, so the walk took ~37
// seconds. Walking the whole address space once is a few thousand calls;
// binary-searching the result is nanoseconds.
//
// The snapshot can go stale if the process maps new memory during discovery.
// For a one-shot startup pass that is the right trade: the object array's
// chunks are already mapped long before injection.
inline std::vector<Region>& regionMap() {
    static std::vector<Region> regions;
    return regions;
}

inline void buildRegionMap() {
    std::vector<Region>& regions = regionMap();
    regions.clear();
    regions.reserve(4096);

    constexpr DWORD kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_EXECUTE_WRITECOPY;

    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    while (VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t end = base + mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 &&
            (mbi.Protect & kReadable) != 0) {
            regions.push_back(Region{base, end});
        }
        if (end <= address) break;  // no forward progress; do not spin
        address = end;
    }
}

// Whether [p, p+n) is committed, readable, and inside one region.
//
// Every read below goes through this. A wrong anchor candidate will point at
// arbitrary bytes, and dereferencing those is how a discovery routine turns
// into a crash in someone else's process.
inline bool readable(const void* p, size_t n) {
    if (p == nullptr || n == 0) return false;
    const uintptr_t start = reinterpret_cast<uintptr_t>(p);
    const uintptr_t finish = start + n;
    if (finish < start) return false;  // overflow

    const std::vector<Region>& regions = regionMap();
    if (regions.empty()) {
        // No snapshot: fall back to the slow but always-current query.
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
        const auto* regionEnd = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
        return static_cast<const uint8_t*>(p) + n <= regionEnd;
    }

    // Last region whose begin is <= start.
    const auto it = std::upper_bound(
        regions.begin(), regions.end(), start,
        [](uintptr_t value, const Region& region) { return value < region.begin; });
    if (it == regions.begin()) return false;
    const Region& region = *(it - 1);
    return start >= region.begin && finish <= region.end;
}

template <typename T>
inline bool readAt(const void* p, T& out) {
    if (!readable(p, sizeof(T))) return false;
    std::memcpy(&out, p, sizeof(T));
    return true;
}

inline bool readPtr(const void* p, const void*& out) {
    return readAt(p, out);
}

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

// FChunkedFixedUObjectArray::NumElementsPerChunk. Not configurable in the
// engine; the chunk index is `index / 65536` everywhere.
constexpr int32_t kChunkSize = 64 * 1024;

// FUObjectItem: Object, Flags, ClusterRootIndex, SerialNumber -> 0x18 aligned.
constexpr size_t kFUObjectItemSize = 0x18;

// UObjectBase: vtable, ObjectFlags, InternalIndex, ClassPrivate, NamePrivate,
// OuterPrivate.
constexpr size_t kUObjectClassPrivate = 0x10;
constexpr size_t kUObjectNamePrivate = 0x18;

// FNameEntryAllocator: Stride == alignof(FNameEntry) == 2.
constexpr size_t kFNameEntryStride = 2;
constexpr uint32_t kFNameBlockOffsetBits = 16;
constexpr uint32_t kFNameMaxBlocks = 8192;

// ---------------------------------------------------------------------------
// FName
// ---------------------------------------------------------------------------

// How the FNameEntry header splits into (bIsWide, Len).
enum class NameLenShift : uint32_t {
    CasePreserving = 1,     // bIsWide:1, Len:15
    Legacy = 6,             // bIsWide:1, ProbeHashBits:5, Len:10
};

// Decode one FNameEntry. `entry` points at the header.
//
// Returns false rather than a guess when the bytes cannot be a name: the caller
// is validating candidates, and "some string came out" is not evidence.
inline bool decodeEntry(const uint8_t* entry, NameLenShift shift, std::string& out) {
    uint16_t header = 0;
    if (!readAt(entry, header)) return false;

    const bool wide = (header & 1u) != 0;
    const uint32_t len = header >> static_cast<uint32_t>(shift);
    if (len == 0 || len > 1024) return false;

    out.clear();
    out.reserve(len);
    if (wide) {
        if (!readable(entry + 2, static_cast<size_t>(len) * sizeof(wchar_t))) return false;
        for (uint32_t i = 0; i < len; ++i) {
            wchar_t wc = 0;
            std::memcpy(&wc, entry + 2 + i * sizeof(wchar_t), sizeof(wc));
            if (wc == 0 || wc > 0x7e) return false;  // names in practice are ASCII
            out.push_back(static_cast<char>(wc));
        }
    } else {
        if (!readable(entry + 2, len)) return false;
        for (uint32_t i = 0; i < len; ++i) {
            const char c = static_cast<char>(entry[2 + i]);
            if (c < 0x20 || c > 0x7e) return false;
            out.push_back(c);
        }
    }
    return true;
}

struct NamePool {
    const uint8_t* blocks = nullptr;  // &Blocks[0]: an array of chunk pointers
    NameLenShift shift = NameLenShift::CasePreserving;

    bool valid() const { return blocks != nullptr; }

    const uint8_t* entryFor(uint32_t id) const {
        if (blocks == nullptr) return nullptr;
        const uint32_t blockIndex = id >> kFNameBlockOffsetBits;
        const uint32_t offset = id & ((1u << kFNameBlockOffsetBits) - 1u);
        if (blockIndex >= kFNameMaxBlocks) return nullptr;
        const void* chunk = nullptr;
        if (!readPtr(blocks + blockIndex * sizeof(void*), chunk)) return nullptr;
        if (chunk == nullptr) return nullptr;
        const uint8_t* entry =
            static_cast<const uint8_t*>(chunk) + static_cast<size_t>(offset) * kFNameEntryStride;
        return readable(entry, kFNameEntryStride) ? entry : nullptr;
    }

    std::string toString(uint32_t id) const {
        const uint8_t* entry = entryFor(id);
        if (entry == nullptr) return {};
        std::string s;
        if (!decodeEntry(entry, shift, s)) return {};
        return s;
    }

    // FName::Number is stored as actual+1 so that zeroed memory means "no
    // instance"; the model-facing form is Name_1, Name_2, ...
    std::string toStringWithNumber(uint32_t id, uint32_t number) const {
        std::string s = toString(id);
        if (s.empty()) return s;
        if (number > 0) {
            s += "_" + std::to_string(number - 1);
        }
        return s;
    }
};

// A pointer that could plausibly live in this process's user-mode address
// space. Used as a cheap pre-filter: VirtualQuery costs far too much to run on
// every qword of a multi-megabyte .data section, and almost every qword there
// is an integer or a zero rather than a pointer.
inline bool plausiblePointer(uint64_t v) {
    return v >= 0x10000ULL && v < 0x00007FFFFFFFFFFFULL && (v & 0x7ULL) == 0;
}

struct NamePoolScan {
    NamePool pool;
    size_t candidatesExamined = 0;
    size_t sectionBytes = 0;
};

// Optional progress callback. Discovery runs once and can take a moment on a
// large .data, so being able to see how far it got matters when it does not
// finish at all.
using TraceFn = void (*)(const char*);

// Find the name pool via the one structural feature nothing else in .data has.
//
// The block array is 8192 pointers, and only the blocks actually in use are
// non-null: a running process has allocated a handful, so the array ends in
// thousands of consecutive nulls -- tens of kilobytes of zeros.
//
// A first attempt scanned every qword and validated each pointer-shaped one.
// It was correct but unusably slow: roughly one qword in eighty looks like a
// pointer in .data, so a 5.4 MB section meant ~67,000 VirtualQuery calls and
// about 90 seconds. Finding the zero run first inverts the cost -- the run is
// unique, so only a handful of candidates ever reach the guarded checks.
inline NamePoolScan findNamePool(const uint8_t* moduleBase, TraceFn trace = nullptr) {
    NamePoolScan result;
    const std::vector<scan::Section> sections = scan::allSections(moduleBase);
    const scan::Section* data = scan::findSection(sections, ".data");
    if (data == nullptr) return result;
    result.sectionBytes = data->size;

    // Long enough to be the array's tail, short enough that a stray zeroed
    // buffer elsewhere does not qualify.
    constexpr size_t kMinZeroRun = 1024;

    const uint64_t* qwords = reinterpret_cast<const uint64_t*>(data->begin);
    const size_t count = data->size / sizeof(uint64_t);

    char progress[96];
    size_t i = 0;
    while (i < count) {
        if (qwords[i] != 0) {
            ++i;
            continue;
        }

        const size_t runStart = i;
        while (i < count && qwords[i] == 0) ++i;
        const size_t runLength = i - runStart;
        if (runLength < kMinZeroRun) continue;

        // Walk back over the allocated blocks. Their count is what tells us
        // where the array begins.
        size_t blockStart = runStart;
        size_t blocks = 0;
        while (blockStart > 0 && blocks < kFNameMaxBlocks &&
               plausiblePointer(qwords[blockStart - 1])) {
            --blockStart;
            ++blocks;
        }
        if (blocks < 2) continue;

        if (trace != nullptr) {
            std::snprintf(progress, sizeof(progress),
                          "namepool: zero run at 0x%zX len=%zu, %zu blocks before it",
                          runStart * sizeof(uint64_t), runLength, blocks);
            trace(progress);
        }

        const uint8_t* candidate = data->begin + blockStart * sizeof(uint64_t);
        for (const NameLenShift shift : {NameLenShift::CasePreserving, NameLenShift::Legacy}) {
            const uint8_t* chunk0 = reinterpret_cast<const uint8_t*>(qwords[blockStart]);
            if (!readable(chunk0, kFNameEntryStride + 4)) continue;

            std::string first;
            if (!decodeEntry(chunk0, shift, first)) continue;
            ++result.candidatesExamined;
            if (first != "None") continue;

            result.pool.blocks = candidate;
            result.pool.shift = shift;
            if (trace != nullptr) trace("namepool: FOUND");
            return result;
        }
    }

    if (trace != nullptr) trace("namepool: no candidate survived");
    return result;
}

// ---------------------------------------------------------------------------
// GUObjectArray
// ---------------------------------------------------------------------------

struct ObjectArray {
    const uint8_t* address = nullptr;   // &GUObjectArray (the FUObjectArray)
    const uint8_t** chunks = nullptr;   // ObjObjects.Objects
    int32_t numElements = 0;
    int32_t numChunks = 0;

    bool valid() const { return address != nullptr; }

    void* objectAt(int32_t index) const {
        if (chunks == nullptr || index < 0 || index >= numElements) return nullptr;
        const void* chunk = nullptr;
        if (!readPtr(chunks + (index / kChunkSize), chunk)) return nullptr;
        if (chunk == nullptr) return nullptr;
        const uint8_t* item = static_cast<const uint8_t*>(chunk) +
                              static_cast<size_t>(index % kChunkSize) * kFUObjectItemSize;
        const void* object = nullptr;
        if (!readPtr(item, object)) return nullptr;
        return const_cast<void*>(object);
    }
};

// Validate a candidate against the default FUObjectArray layout.
//
// The counts are the discriminator: NumChunks must agree with NumElements, the
// maxima must bound the current values, and the first chunk must contain a
// readable object. Random .data does not satisfy all of that.
inline bool looksLikeObjectArray(const uint8_t* p, ObjectArray& out) {
    const void* chunks = nullptr;
    int32_t maxElements = 0, numElements = 0, maxChunks = 0, numChunks = 0;

    if (!readPtr(p + 0x10, chunks)) return false;
    if (!readAt(p + 0x20, maxElements)) return false;
    if (!readAt(p + 0x24, numElements)) return false;
    if (!readAt(p + 0x28, maxChunks)) return false;
    if (!readAt(p + 0x2C, numChunks)) return false;

    if (numElements < 1000 || numElements > 20000000) return false;
    if (numChunks < 1 || numChunks > 4096) return false;

    const int32_t expected = (numElements + kChunkSize - 1) / kChunkSize;
    if (numChunks < expected || numChunks > expected + 1) return false;
    if (maxChunks < numChunks || maxElements < numElements) return false;
    if (chunks == nullptr) return false;
    if (!readable(chunks, static_cast<size_t>(numChunks) * sizeof(void*))) return false;

    // The first chunk must exist and its first slot must be a real object with
    // a readable UObject header.
    const void* chunk0 = nullptr;
    if (!readPtr(chunks, chunk0) || chunk0 == nullptr) return false;
    if (!readable(chunk0, kFUObjectItemSize)) return false;
    const void* object0 = nullptr;
    if (!readPtr(chunk0, object0) || object0 == nullptr) return false;
    if (!readable(object0, kUObjectNamePrivate + sizeof(uint64_t))) return false;

    out.address = p;
    out.chunks = static_cast<const uint8_t**>(const_cast<void*>(chunks));
    out.numElements = numElements;
    out.numChunks = numChunks;
    return true;
}

// Path 1 of the column: StaticConstructObject_Internal references GUObjectArray
// internally, so walk its instructions and validate every global it touches.
//
// This is preferred over an AOB for GUObjectArray because the function is
// guaranteed to exist and guaranteed to reference the array, whereas the
// array's layout is exactly the thing that varies.
inline ObjectArray findObjectArray(const uint8_t* staticConstructObject, size_t sweepBytes) {
    ObjectArray found;
    if (staticConstructObject == nullptr) return found;

    const std::vector<const uint8_t*> targets =
        disasm::ripRelativeTargets(staticConstructObject, sweepBytes);
    for (const uint8_t* candidate : targets) {
        ObjectArray probe;
        if (looksLikeObjectArray(candidate, probe)) return probe;
    }
    return found;
}

// ---------------------------------------------------------------------------
// Object introspection
// ---------------------------------------------------------------------------

inline std::string classNameOf(const NamePool& pool, const void* cls) {
    if (cls == nullptr || !pool.valid()) return {};
    const void* classOfClass = nullptr;
    if (!readPtr(static_cast<const uint8_t*>(cls) + kUObjectClassPrivate, classOfClass)) {
        return {};
    }
    // A UClass's own ClassPrivate points at UClass::StaticClass(); if that is
    // unreadable the pointer was not a UClass and the name would be garbage.
    if (!readable(classOfClass, kUObjectNamePrivate + sizeof(uint64_t))) return {};

    uint64_t name = 0;
    if (!readAt(static_cast<const uint8_t*>(cls) + kUObjectNamePrivate, name)) return {};
    return pool.toStringWithNumber(static_cast<uint32_t>(name & 0xffffffffu),
                                   static_cast<uint32_t>(name >> 32));
}

inline std::string objectNameOf(const NamePool& pool, const void* obj) {
    if (obj == nullptr || !pool.valid()) return {};
    uint64_t name = 0;
    if (!readAt(static_cast<const uint8_t*>(obj) + kUObjectNamePrivate, name)) return {};
    return pool.toStringWithNumber(static_cast<uint32_t>(name & 0xffffffffu),
                                   static_cast<uint32_t>(name >> 32));
}

// Enumerate objects of a given class name, which is the column's "拿到之后怎么用"
// recipe: walk the array, read each object's class, compare the name.
//
// This is also the end-to-end check that the whole chain works -- array layout,
// object offsets, and FName decoding all have to be right for a single hit to
// come out with a plausible name.
struct ObjectHit {
    void* object = nullptr;
    std::string name;
    std::string className;
};

inline std::vector<ObjectHit> findObjectsByClass(const ObjectArray& objects, const NamePool& pool,
                                                 const char* wanted, size_t maxHits = 16) {
    std::vector<ObjectHit> hits;
    if (!objects.valid() || !pool.valid() || wanted == nullptr) return hits;

    for (int32_t i = 0; i < objects.numElements && hits.size() < maxHits; ++i) {
        void* obj = objects.objectAt(i);
        if (obj == nullptr) continue;

        const void* cls = nullptr;
        if (!readPtr(static_cast<const uint8_t*>(obj) + kUObjectClassPrivate, cls)) continue;
        if (cls == nullptr) continue;

        const std::string clsName = classNameOf(pool, cls);
        if (clsName != wanted) continue;

        ObjectHit hit;
        hit.object = obj;
        hit.className = clsName;
        hit.name = objectNameOf(pool, obj);
        hits.push_back(std::move(hit));
    }
    return hits;
}

// Distinct class names seen across the array, with their object counts. Slower
// than a single-class query, but it is the cheapest way to show that the array
// is being walked correctly rather than just that one lookup happened to work.
inline std::vector<std::pair<std::string, int32_t>> classHistogram(const ObjectArray& objects,
                                                                   const NamePool& pool,
                                                                   size_t maxClasses = 12) {
    std::unordered_map<std::string, int32_t> counts;
    if (!objects.valid() || !pool.valid()) return {};

    for (int32_t i = 0; i < objects.numElements; ++i) {
        void* obj = objects.objectAt(i);
        if (obj == nullptr) continue;
        const void* cls = nullptr;
        if (!readPtr(static_cast<const uint8_t*>(obj) + kUObjectClassPrivate, cls)) continue;
        if (cls == nullptr) continue;
        const std::string clsName = classNameOf(pool, cls);
        if (clsName.empty()) continue;
        ++counts[clsName];
    }

    std::vector<std::pair<std::string, int32_t>> out(counts.begin(), counts.end());
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    if (out.size() > maxClasses) out.resize(maxClasses);
    return out;
}

}  // namespace ue
