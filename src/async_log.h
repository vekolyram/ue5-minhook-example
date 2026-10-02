#pragma once
//
// Lock-free call log.
//
// The detour runs on whatever thread the engine happens to be constructing an
// object on, and StaticConstructObject_Internal is called thousands of times
// during startup. Anything expensive there -- printf, file I/O, a mutex, a heap
// allocation -- shows up as a stutter at best and a deadlock at worst.
//
// So the detour does exactly one thing: copy a POD record into a preallocated
// slot of a bounded MPMC ring (Vyukov's algorithm). A consumer thread drains it
// to a file. If the ring is full the record is dropped and counted; the game
// never blocks on the logger.
//
#include <windows.h>

#include <share.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>

namespace asynclog {

// One observed call. Kept POD and small so the hot path is a plain memcpy.
struct Record {
    uint64_t seq = 0;        // consumer-side ordering aid
    uint32_t threadId = 0;
    uint32_t flags70 = 0;    // [params+0x70], the dword the prologue itself reads
    void* params = nullptr;  // rcx: &FStaticConstructObjectParameters
    void* cls = nullptr;     // [params+0x00] const UClass*
    void* outer = nullptr;   // [params+0x08] UObject*
    uint64_t name = 0;       // [params+0x10] FName (ComparisonIndex + Number)
    void* retAddr = nullptr; // who asked for the object
    void* result = nullptr;  // UObject* the original returned
};

namespace detail {

struct Slot {
    std::atomic<uint64_t> sequence{0};
    Record record{};
};

}  // namespace detail

class Ring {
public:
    // Resolves a UClass pointer to a readable name. Called from the CONSUMER
    // thread only, never from the detour: walking the name pool is far too
    // expensive for a function that runs ~1600 times a second.
    using ClassNameResolver = std::string (*)(const void* cls);

    ~Ring() { stop(); }

    // `capacity` is rounded up to a power of two. Opens `path` for writing.
    // `header`, when given, is written before the consumer thread starts, so it
    // cannot interleave with drained records.
    bool start(const wchar_t* path, size_t capacity = 1u << 16, const wchar_t* header = nullptr,
               ClassNameResolver resolveClass = nullptr) {
        if (running_.load()) return false;
        resolveClass_ = resolveClass;

        size_t cap = 1;
        while (cap < capacity) cap <<= 1;
        mask_ = cap - 1;

        slots_ = new (std::nothrow) detail::Slot[cap];
        if (slots_ == nullptr) return false;
        for (size_t i = 0; i < cap; ++i) {
            slots_[i].sequence.store(i, std::memory_order_relaxed);
        }

        // _SH_DENYNO, not _wfopen_s: the default is exclusive, which locks the
        // log for as long as the game runs -- exactly when you want to tail it.
        file_ = _wfsopen(path, L"w, ccs=UTF-8", _SH_DENYNO);
        if (file_ == nullptr) {
            delete[] slots_;
            slots_ = nullptr;
            return false;
        }        if (header != nullptr) {
            std::fwprintf(file_, L"%s\n", header);
            std::fflush(file_);
        }

        stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (stopEvent_ == nullptr) {
            std::fclose(file_);
            file_ = nullptr;
            delete[] slots_;
            slots_ = nullptr;
            return false;
        }

        running_.store(true);
        thread_ = CreateThread(nullptr, 0, &Ring::threadProc, this, 0, nullptr);
        if (thread_ == nullptr) {
            running_.store(false);
            CloseHandle(stopEvent_);
            stopEvent_ = nullptr;
            std::fclose(file_);
            file_ = nullptr;
            delete[] slots_;
            slots_ = nullptr;
            return false;
        }
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        if (stopEvent_ != nullptr) SetEvent(stopEvent_);
        if (thread_ != nullptr) {
            WaitForSingleObject(thread_, 5000);
            CloseHandle(thread_);
            thread_ = nullptr;
        }
        drain();  // last records produced before the flag flipped
        if (file_ != nullptr) {
            std::fclose(file_);
            file_ = nullptr;
        }
        if (stopEvent_ != nullptr) {
            CloseHandle(stopEvent_);
            stopEvent_ = nullptr;
        }
        delete[] slots_;
        slots_ = nullptr;
    }

    // Hot path. Lock-free, allocation-free, never blocks.
    void push(const Record& r) noexcept {
        if (slots_ == nullptr) return;
        size_t pos = enqueue_.load(std::memory_order_relaxed);
        for (;;) {
            detail::Slot& slot = slots_[pos & mask_];
            const intptr_t dif =
                static_cast<intptr_t>(slot.sequence.load(std::memory_order_acquire)) -
                static_cast<intptr_t>(pos);
            if (dif == 0) {
                if (enqueue_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    slot.record = r;
                    slot.sequence.store(pos + 1, std::memory_order_release);
                    return;
                }
            } else if (dif < 0) {
                dropped_.fetch_add(1, std::memory_order_relaxed);
                return;
            } else {
                pos = enqueue_.load(std::memory_order_relaxed);
            }
        }
    }

    // A free-text line, written synchronously.
    //
    // For startup summaries and other rare, human-authored output. It takes the
    // same lock drain() uses so a note cannot interleave with a record. Never
    // call this from the detour -- it blocks.
    void note(const wchar_t* text) {
        if (file_ == nullptr || text == nullptr) return;
        std::lock_guard<std::mutex> guard(fileLock_);
        std::fwprintf(file_, L"%s\n", text);
        std::fflush(file_);
    }

    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }
    uint64_t written() const { return written_.load(std::memory_order_relaxed); }

private:
    static DWORD WINAPI threadProc(LPVOID self) {
        static_cast<Ring*>(self)->run();
        return 0;
    }

    void run() {
        while (running_.load(std::memory_order_relaxed)) {
            drain();
            // Polling beats signalling here: a SetEvent from the hot path is a
            // syscall, and 4 ms of latency on a log line costs nothing.
            WaitForSingleObject(stopEvent_, 4);
        }
        drain();
    }

    bool pop(Record& out) {
        size_t pos = dequeue_.load(std::memory_order_relaxed);
        for (;;) {
            detail::Slot& slot = slots_[pos & mask_];
            const intptr_t dif =
                static_cast<intptr_t>(slot.sequence.load(std::memory_order_acquire)) -
                static_cast<intptr_t>(pos + 1);
            if (dif == 0) {
                if (dequeue_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    out = slot.record;
                    slot.sequence.store(pos + mask_ + 1, std::memory_order_release);
                    return true;
                }
            } else if (dif < 0) {
                return false;  // empty
            } else {
                pos = dequeue_.load(std::memory_order_relaxed);
            }
        }
    }

    void drain() {
        if (file_ == nullptr) return;
        std::lock_guard<std::mutex> guard(fileLock_);
        Record r;
        int flushed = 0;
        while (pop(r)) {
            std::fwprintf(file_,
                          L"seq=%llu tid=%lu params=%p class=%p outer=%p name=%016llX "
                          L"flags70=%08X result=%p ret=%p",
                          static_cast<unsigned long long>(r.seq), r.threadId, r.params, r.cls,
                          r.outer, static_cast<unsigned long long>(r.name), r.flags70, r.result,
                          r.retAddr);
            if (resolveClass_ != nullptr) {
                // The same handful of UClasses accounts for almost every call,
                // so one lookup per distinct pointer is enough.
                auto it = nameCache_.find(r.cls);
                if (it == nameCache_.end()) {
                    it = nameCache_.emplace(r.cls, resolveClass_(r.cls)).first;
                }
                std::fwprintf(file_, L" classname=%hs",
                              it->second.empty() ? "?" : it->second.c_str());
            }
            std::fputwc(L'\n', file_);
            written_.fetch_add(1, std::memory_order_relaxed);
            if (++flushed >= 256) {
                std::fflush(file_);
                flushed = 0;
            }
        }
        if (flushed != 0) std::fflush(file_);
    }

    detail::Slot* slots_ = nullptr;
    size_t mask_ = 0;
    std::FILE* file_ = nullptr;
    HANDLE stopEvent_ = nullptr;
    HANDLE thread_ = nullptr;
    ClassNameResolver resolveClass_ = nullptr;
    std::unordered_map<const void*, std::string> nameCache_;
    // Guards file_ between the consumer thread's batches and note(). Not touched
    // by the detour.
    std::mutex fileLock_;

    // Both counters share a cache line with nothing else hot: they are written
    // by different threads every call.
    alignas(64) std::atomic<size_t> enqueue_{0};
    alignas(64) std::atomic<size_t> dequeue_{0};
    alignas(64) std::atomic<uint64_t> dropped_{0};
    alignas(64) std::atomic<uint64_t> written_{0};
    std::atomic<bool> running_{false};
};

}  // namespace asynclog
