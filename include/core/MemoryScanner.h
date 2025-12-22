#pragma once

#include "core/TargetProcess.h"
#include <vector>
#include <cstdint>
#include <string>
#include <atomic>
#include <cstddef>
#include <mutex>

namespace core {

enum class ValueType {
    Byte,
    Int16,
    Int32,
    Int64,
    Float,
    Double,
    ArrayOfByte,
    String
};

enum class ScanMode {
    Exact,
    UnknownInitial,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    GreaterThan,
    LessThan,
    Between,
    Aob
};

struct ScanResult {
    uintptr_t address;
    uint64_t raw; // stored bits of last observed value
};

struct ScanParams {
    ValueType type{ValueType::Int32};
    ScanMode mode{ScanMode::Exact};
    std::string value1;
    std::string value2; // used for Between
    uintptr_t startAddress{0};
    uintptr_t endAddress{0}; // 0 means no cap
    size_t alignment{0}; // 0 -> default sizeof(type)
    bool requireWritable{false};
    bool requireExecutable{false};
    bool hexInput{false};
    bool skipMaskedRegions{true};
};

class MemoryScanner {
public:
    explicit MemoryScanner(const TargetProcess &proc);

    bool firstScan(const ScanParams &params);
    bool nextScan(const ScanParams &params);
    void requestCancel() { cancel_.store(true, std::memory_order_relaxed); }
    void resetCancel() { cancel_.store(false, std::memory_order_relaxed); }
    size_t estimateWork(const ScanParams &params) const;
    void setProgressSink(std::atomic<size_t> *doneBytes, size_t totalBytes);

    const std::vector<ScanResult> &results() const { return results_; }
    void restoreResults(const std::vector<ScanResult> &results);
    void reset() { results_.clear(); shadowRegions_.clear(); cleanupShadowFile(); }
    static bool parseAobPattern(const std::string &pattern, std::vector<int> &out);
    bool hasShadowCopy() const { return !shadowRegions_.empty(); }

private:
    const TargetProcess &proc_;
    std::vector<ScanResult> results_;

    struct MemoryRegionSnapshot {
        uintptr_t start;
        size_t size;
        uint64_t fileOffset; // Offset in the temporary shadow file
    };
    std::vector<MemoryRegionSnapshot> shadowRegions_;
    std::string shadowFilePath_;
    int shadowFd_{-1};
    void *shadowMap_{nullptr};
    size_t shadowMapSize_{0};
    void cleanupShadowFile();

    template <typename T>
    bool parseValue(const std::string &s, T &out) const;
    template <typename T>
    void scanExact(const T &needle, size_t alignment, const ScanParams &params);
    template <typename T>
    void snapshotAll(size_t alignment, const ScanParams &params);
    template <typename T>
    void rescan(const ScanParams &params, const T *needle, const T *needle2 = nullptr);
    template <typename T>
    void rescanShadow(const ScanParams &params, const T *needle, const T *needle2 = nullptr);
    template <typename T>
    void scanExactParallel(const T &needle, size_t alignment, const ScanParams &params);
    template <typename T>
    void snapshotAllParallel(size_t alignment, const ScanParams &params);
    template <typename T>
    uint64_t packRaw(const T &v) const;
    bool passesRegionFilter(const ScanParams &params, const MemoryRegion &region) const;
    std::pair<uintptr_t, uintptr_t> clampRange(const ScanParams &params, const MemoryRegion &region) const;
    bool isMaskedRegion(const MemoryRegion &region) const;

    // Special scanners
    void scanArrayOfByte(const ScanParams &params);
    void scanString(const ScanParams &params);
    void createShadowCopy(const ScanParams &params);

    std::atomic<bool> cancel_{false};
    std::atomic<size_t> *progressDone_{nullptr};
    size_t progressTotal_{0};
    void progressAdd(size_t bytes);
};

} // namespace core
