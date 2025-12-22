#include "core/MemoryScanner.h"

#include <cstring>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <thread>
#include <mutex>
#include <fstream>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

namespace core {

MemoryScanner::MemoryScanner(const TargetProcess &proc) : proc_(proc) {}

size_t MemoryScanner::estimateWork(const ScanParams &params) const {
    size_t total = 0;
    for (const auto &region : proc_.regions()) {
        if (!passesRegionFilter(params, region)) continue;
        auto [start, end] = clampRange(params, region);
        if (end > start) total += (end - start);
    }
    return total;
}

void MemoryScanner::setProgressSink(std::atomic<size_t> *doneBytes, size_t totalBytes) {
    progressDone_ = doneBytes;
    progressTotal_ = totalBytes;
    if (progressDone_) progressDone_->store(0, std::memory_order_relaxed);
}

void MemoryScanner::progressAdd(size_t bytes) {
    if (!progressDone_ || progressTotal_ == 0) return;
    progressDone_->fetch_add(bytes, std::memory_order_relaxed);
}

void MemoryScanner::restoreResults(const std::vector<ScanResult> &results) {
    results_ = results;
}

bool MemoryScanner::parseAobPattern(const std::string &patternStr, std::vector<int> &pattern) {
    pattern.clear();
    if (patternStr.empty()) return false;
    std::istringstream iss(patternStr);
    std::string tok;
    while (iss >> tok) {
        if (tok.empty()) continue;
        // Normalize to uppercase
        for (auto &ch : tok) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        if (tok == "??" || tok == "?" || tok == "**") {
            pattern.push_back(-1);
        } else {
            char *end = nullptr;
            long val = std::strtol(tok.c_str(), &end, 16);
            if (!end || *end != '\0') {
                pattern.clear();
                return false;
            }
            pattern.push_back(static_cast<int>(val & 0xFF));
        }
    }
    return !pattern.empty();
}

template <typename T>
bool MemoryScanner::parseValue(const std::string &s, T &out) const {
    std::istringstream iss(s);
    iss >> out;
    return !iss.fail();
}

template <typename T>
void MemoryScanner::scanExact(const T &needle, size_t alignment, const ScanParams &params) {
    results_.clear();
    scanExactParallel<T>(needle, alignment, params);
}

template <typename T>
void MemoryScanner::snapshotAll(size_t alignment, const ScanParams &params) {
    results_.clear();
    snapshotAllParallel<T>(alignment, params);
}

template <typename T>
void MemoryScanner::rescan(const ScanParams &params, const T *needle, const T *needle2) {
    std::vector<ScanResult> filtered;
    for (const auto &res : results_) {
        if (cancel_.load(std::memory_order_relaxed)) break;
        T value;
        if (!proc_.readMemory(res.address, &value, sizeof(T))) continue;
        bool keep = false;
        switch (params.mode) {
            case ScanMode::Exact:
                keep = (needle && value == *needle);
                break;
            case ScanMode::Changed:
                keep = (packRaw(value) != res.raw);
                break;
            case ScanMode::Unchanged:
                keep = (packRaw(value) == res.raw);
                break;
            case ScanMode::Increased: {
                T prev;
                std::memcpy(&prev, &res.raw, sizeof(T));
                keep = value > prev;
                break;
            }
            case ScanMode::Decreased: {
                T prev;
                std::memcpy(&prev, &res.raw, sizeof(T));
                keep = value < prev;
                break;
            }
            case ScanMode::UnknownInitial:
                keep = true;
                break;
            case ScanMode::GreaterThan:
                keep = (needle && value > *needle);
                break;
            case ScanMode::LessThan:
                keep = (needle && value < *needle);
                break;
            case ScanMode::Between:
                keep = (needle && needle2 && value >= *needle && value <= *needle2);
                break;
            case ScanMode::Aob:
                keep = false;
                break;
        }
        if (keep) {
            filtered.push_back(ScanResult{res.address, packRaw(value)});
        }
    }
    results_.swap(filtered);
}

template <typename T>
void MemoryScanner::scanExactParallel(const T &needle, size_t alignment, const ScanParams &params) {
    auto regions = proc_.regions();
    constexpr size_t kChunk = 1024 * 1024;
    constexpr size_t kMaxResults = 20000000;
    size_t workerCount = std::max<size_t>(1, std::thread::hardware_concurrency());
    std::mutex mtx;
    std::atomic<bool> limitReached{false};
    std::vector<std::thread> threads;
    threads.reserve(workerCount);

    for (size_t t = 0; t < workerCount; ++t) {
        threads.emplace_back([&, t]() {
            std::vector<unsigned char> buffer(kChunk);
            std::vector<ScanResult> local;
            local.reserve(4096);

            for (size_t ri = t; ri < regions.size(); ri += workerCount) {
                if (cancel_.load(std::memory_order_relaxed) || limitReached.load(std::memory_order_relaxed)) break;
                const auto &region = regions[ri];
                if (!passesRegionFilter(params, region)) continue;
                auto [start, end] = clampRange(params, region);

                for (uintptr_t addr = start; addr + sizeof(T) <= end; addr += kChunk) {
                    if (cancel_.load(std::memory_order_relaxed) || limitReached.load(std::memory_order_relaxed)) break;

                    size_t toRead = std::min(kChunk, end - addr);
                    if (buffer.size() < toRead) buffer.resize(toRead);
                    
                    if (!proc_.readMemory(addr, buffer.data(), toRead)) continue;
                    progressAdd(toRead);

                    if (alignment == sizeof(T)) {
                        const T* ptr = reinterpret_cast<const T*>(buffer.data());
                        size_t count = toRead / sizeof(T);
                        for (size_t i = 0; i < count; ++i) {
                            if (ptr[i] == needle) {
                                local.push_back(ScanResult{addr + i * sizeof(T), packRaw(ptr[i])});
                            }
                        }
                    } 
                    else {
                        for (size_t offset = 0; offset + sizeof(T) <= toRead; offset += alignment) {
                            T value;
                            std::memcpy(&value, buffer.data() + offset, sizeof(T));
                            if (value == needle) {
                                local.push_back(ScanResult{addr + offset, packRaw(value)});
                            }
                        }
                    }
                    
                    if (local.size() >= 10000) {
                        std::lock_guard<std::mutex> lock(mtx);
                        if (results_.size() + local.size() > kMaxResults) {
                            limitReached.store(true, std::memory_order_relaxed);
                        } else {
                            results_.insert(results_.end(), local.begin(), local.end());
                        }
                        local.clear();
                    }
                }
            }
            if (!local.empty()) {
                std::lock_guard<std::mutex> lock(mtx);
                if (results_.size() + local.size() <= kMaxResults) {
                    results_.insert(results_.end(), local.begin(), local.end());
                } else {
                     limitReached.store(true, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto &th : threads) th.join();
}

template <typename T>
void MemoryScanner::snapshotAllParallel(size_t alignment, const ScanParams &params) {
    auto regions = proc_.regions();
    constexpr size_t kChunk = 1024 * 1024; // 1MB chunk
    constexpr size_t kMaxResults = 20000000;
    size_t workerCount = std::max<size_t>(1, std::thread::hardware_concurrency());
    std::mutex mtx;
    std::atomic<bool> limitReached{false};
    std::vector<std::thread> threads;
    threads.reserve(workerCount);

    for (size_t t = 0; t < workerCount; ++t) {
        threads.emplace_back([&, t]() {
            std::vector<unsigned char> buffer(kChunk);
            std::vector<ScanResult> local;
            local.reserve(4096);

            for (size_t ri = t; ri < regions.size(); ri += workerCount) {
                if (cancel_.load(std::memory_order_relaxed) || limitReached.load(std::memory_order_relaxed)) break;
                const auto &region = regions[ri];
                if (!passesRegionFilter(params, region)) continue;
                auto [start, end] = clampRange(params, region);

                for (uintptr_t addr = start; addr + sizeof(T) <= end; addr += kChunk) {
                    if (cancel_.load(std::memory_order_relaxed) || limitReached.load(std::memory_order_relaxed)) break;

                    size_t toRead = std::min(kChunk, end - addr);
                    if (buffer.size() < toRead) buffer.resize(toRead);

                    if (!proc_.readMemory(addr, buffer.data(), toRead)) continue;
                    progressAdd(toRead);

                    // FAST PATH: Aligned bulk copy
                    if (alignment == sizeof(T)) {
                        const T* ptr = reinterpret_cast<const T*>(buffer.data());
                        size_t count = toRead / sizeof(T);
                        for (size_t i = 0; i < count; ++i) {
                            local.push_back(ScanResult{addr + i * sizeof(T), packRaw(ptr[i])});
                        }
                    } 
                    // GENERIC PATH
                    else {
                        for (size_t offset = 0; offset + sizeof(T) <= toRead; offset += alignment) {
                            T value;
                            std::memcpy(&value, buffer.data() + offset, sizeof(T));
                            local.push_back(ScanResult{addr + offset, packRaw(value)});
                        }
                    }

                    if (local.size() >= 10000) {
                        std::lock_guard<std::mutex> lock(mtx);
                        if (results_.size() + local.size() > kMaxResults) {
                            limitReached.store(true, std::memory_order_relaxed);
                        } else {
                            results_.insert(results_.end(), local.begin(), local.end());
                        }
                        local.clear();
                    }
                }
            }
            if (!local.empty()) {
                std::lock_guard<std::mutex> lock(mtx);
                if (results_.size() + local.size() <= kMaxResults) {
                    results_.insert(results_.end(), local.begin(), local.end());
                } else {
                    limitReached.store(true, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto &th : threads) th.join();
}

template <typename T>
uint64_t MemoryScanner::packRaw(const T &v) const {
    uint64_t raw = 0;
    std::memcpy(&raw, &v, sizeof(T));
    return raw;
}

bool MemoryScanner::firstScan(const ScanParams &params) {
    cancel_.store(false, std::memory_order_relaxed);
    ScanParams p = params;
    if (p.hexInput) {
        if (!p.value1.empty() && p.value1.rfind("0x", 0) != 0) {
            p.value1 = "0x" + p.value1;
        }
        if (!p.value2.empty() && p.value2.rfind("0x", 0) != 0) {
            p.value2 = "0x" + p.value2;
        }
    }
    if (p.alignment == 0) {
        switch (p.type) {
            case ValueType::Byte: p.alignment = sizeof(int8_t); break;
            case ValueType::Int16: p.alignment = sizeof(int16_t); break;
            case ValueType::Int32: p.alignment = sizeof(int32_t); break;
            case ValueType::Int64: p.alignment = sizeof(int64_t); break;
            case ValueType::Float: p.alignment = sizeof(float); break;
            case ValueType::Double: p.alignment = sizeof(double); break;
            case ValueType::ArrayOfByte: p.alignment = 1; break;
            case ValueType::String: p.alignment = 1; break;
        }
    }

    switch (p.type) {
        case ValueType::Byte: {
            int8_t v;
            if (p.mode != ScanMode::UnknownInitial && !parseValue(p.value1, v)) return false;
            if (p.mode == ScanMode::UnknownInitial) createShadowCopy(p);
            else scanExact<int8_t>(v, p.alignment, p);
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Int16: {
            int16_t v;
            if (p.mode != ScanMode::UnknownInitial && !parseValue(p.value1, v)) return false;
            if (p.mode == ScanMode::UnknownInitial) createShadowCopy(p);
            else scanExact<int16_t>(v, p.alignment, p);
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Float: {
            float v;
            if (p.mode != ScanMode::UnknownInitial && !parseValue(p.value1, v)) return false;
            if (p.mode == ScanMode::UnknownInitial) createShadowCopy(p);
            else scanExact<float>(v, p.alignment, p);
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Double: {
            double v;
            if (p.mode != ScanMode::UnknownInitial && !parseValue(p.value1, v)) return false;
            if (p.mode == ScanMode::UnknownInitial) createShadowCopy(p);
            else scanExact<double>(v, p.alignment, p);
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Int32: {
            int32_t v;
            if (p.mode != ScanMode::UnknownInitial && !parseValue(p.value1, v)) return false;
            if (p.mode == ScanMode::UnknownInitial) createShadowCopy(p);
            else scanExact<int32_t>(v, p.alignment, p);
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Int64: {
            int64_t v;
            if (p.mode != ScanMode::UnknownInitial && !parseValue(p.value1, v)) return false;
            if (p.mode == ScanMode::UnknownInitial) createShadowCopy(p);
            else scanExact<int64_t>(v, p.alignment, p);
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::ArrayOfByte: {
            scanArrayOfByte(p);
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::String: {
            scanString(p);
            return !cancel_.load(std::memory_order_relaxed);
        }
    }
    return false;
}

bool MemoryScanner::nextScan(const ScanParams &params) {
    cancel_.store(false, std::memory_order_relaxed);
    ScanParams p = params;
    if (p.hexInput) {
        if (!p.value1.empty() && p.value1.rfind("0x", 0) != 0) {
            p.value1 = "0x" + p.value1;
        }
        if (!p.value2.empty() && p.value2.rfind("0x", 0) != 0) {
            p.value2 = "0x" + p.value2;
        }
    }
    if (p.alignment == 0) {
        switch (p.type) {
            case ValueType::Byte: p.alignment = sizeof(int8_t); break;
            case ValueType::Int16: p.alignment = sizeof(int16_t); break;
            case ValueType::Int32: p.alignment = sizeof(int32_t); break;
            case ValueType::Int64: p.alignment = sizeof(int64_t); break;
            case ValueType::Float: p.alignment = sizeof(float); break;
            case ValueType::Double: p.alignment = sizeof(double); break;
            case ValueType::ArrayOfByte: p.alignment = 1; break;
            case ValueType::String: p.alignment = 1; break;
        }
    }
    switch (p.type) {
        case ValueType::Byte: {
            int8_t v;
            if (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) {
                if (!parseValue(p.value1, v)) return false;
            }
            int8_t v2{};
            if (p.mode == ScanMode::Between) {
                if (!parseValue(p.value2, v2)) return false;
            }
            const int8_t *ptr = (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) ? &v : nullptr;
            const int8_t *ptr2 = (p.mode == ScanMode::Between) ? &v2 : nullptr;
            
            if (results_.empty() && !shadowRegions_.empty()) {
                rescanShadow<int8_t>(p, ptr, ptr2);
            } else {
                rescan<int8_t>(p, ptr, ptr2);
            }
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Int16: {
            int16_t v;
            if (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) {
                if (!parseValue(p.value1, v)) return false;
            }
            int16_t v2{};
            if (p.mode == ScanMode::Between) {
                if (!parseValue(p.value2, v2)) return false;
            }
            const int16_t *ptr = (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) ? &v : nullptr;
            const int16_t *ptr2 = (p.mode == ScanMode::Between) ? &v2 : nullptr;
            if (results_.empty() && !shadowRegions_.empty()) {
                rescanShadow<int16_t>(p, ptr, ptr2);
            } else {
                rescan<int16_t>(p, ptr, ptr2);
            }
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Int32: {
            int32_t v;
            if (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) {
                if (!parseValue(p.value1, v)) return false;
            }
            int32_t v2{};
            if (p.mode == ScanMode::Between) {
                if (!parseValue(p.value2, v2)) return false;
            }
            const int32_t *ptr = (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) ? &v : nullptr;
            const int32_t *ptr2 = (p.mode == ScanMode::Between) ? &v2 : nullptr;
            if (results_.empty() && !shadowRegions_.empty()) {
                rescanShadow<int32_t>(p, ptr, ptr2);
            } else {
                rescan<int32_t>(p, ptr, ptr2);
            }
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Int64: {
            int64_t v;
            if (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) {
                if (!parseValue(p.value1, v)) return false;
            }
            int64_t v2{};
            if (p.mode == ScanMode::Between) {
                if (!parseValue(p.value2, v2)) return false;
            }
            const int64_t *ptr = (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) ? &v : nullptr;
            const int64_t *ptr2 = (p.mode == ScanMode::Between) ? &v2 : nullptr;
            if (results_.empty() && !shadowRegions_.empty()) {
                rescanShadow<int64_t>(p, ptr, ptr2);
            } else {
                rescan<int64_t>(p, ptr, ptr2);
            }
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Float: {
            float v;
            if (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) {
                if (!parseValue(p.value1, v)) return false;
            }
            float v2{};
            if (p.mode == ScanMode::Between) {
                if (!parseValue(p.value2, v2)) return false;
            }
            const float *ptr = (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) ? &v : nullptr;
            const float *ptr2 = (p.mode == ScanMode::Between) ? &v2 : nullptr;
            if (results_.empty() && !shadowRegions_.empty()) {
                rescanShadow<float>(p, ptr, ptr2);
            } else {
                rescan<float>(p, ptr, ptr2);
            }
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::Double: {
            double v;
            if (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) {
                if (!parseValue(p.value1, v)) return false;
            }
            double v2{};
            if (p.mode == ScanMode::Between) {
                if (!parseValue(p.value2, v2)) return false;
            }
            const double *ptr = (p.mode == ScanMode::Exact || p.mode == ScanMode::GreaterThan || p.mode == ScanMode::LessThan || p.mode == ScanMode::Between) ? &v : nullptr;
            const double *ptr2 = (p.mode == ScanMode::Between) ? &v2 : nullptr;
            if (results_.empty() && !shadowRegions_.empty()) {
                rescanShadow<double>(p, ptr, ptr2);
            } else {
                rescan<double>(p, ptr, ptr2);
            }
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::ArrayOfByte: {
            // AOB rescans aren't meaningful with delta comparisons; rerun initial scan
            scanArrayOfByte(p);
            return !cancel_.load(std::memory_order_relaxed);
        }
        case ValueType::String: {
            scanString(p);
            return !cancel_.load(std::memory_order_relaxed);
        }
    }
    return false;
}

// Explicit template instantiations
template bool MemoryScanner::parseValue<int32_t>(const std::string &, int32_t &) const;
template bool MemoryScanner::parseValue<int16_t>(const std::string &, int16_t &) const;
template bool MemoryScanner::parseValue<int8_t>(const std::string &, int8_t &) const;
template bool MemoryScanner::parseValue<int64_t>(const std::string &, int64_t &) const;
template bool MemoryScanner::parseValue<float>(const std::string &, float &) const;
template bool MemoryScanner::parseValue<double>(const std::string &, double &) const;

template void MemoryScanner::scanExact<int32_t>(const int32_t &, size_t, const ScanParams &);
template void MemoryScanner::scanExact<float>(const float &, size_t, const ScanParams &);
template void MemoryScanner::scanExact<double>(const double &, size_t, const ScanParams &);
template void MemoryScanner::scanExact<int8_t>(const int8_t &, size_t, const ScanParams &);
template void MemoryScanner::scanExact<int16_t>(const int16_t &, size_t, const ScanParams &);
template void MemoryScanner::scanExact<int64_t>(const int64_t &, size_t, const ScanParams &);
template void MemoryScanner::scanExactParallel<int32_t>(const int32_t &, size_t, const ScanParams &);
template void MemoryScanner::scanExactParallel<float>(const float &, size_t, const ScanParams &);
template void MemoryScanner::scanExactParallel<double>(const double &, size_t, const ScanParams &);
template void MemoryScanner::scanExactParallel<int8_t>(const int8_t &, size_t, const ScanParams &);
template void MemoryScanner::scanExactParallel<int16_t>(const int16_t &, size_t, const ScanParams &);
template void MemoryScanner::scanExactParallel<int64_t>(const int64_t &, size_t, const ScanParams &);

template void MemoryScanner::snapshotAll<int32_t>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAll<float>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAll<double>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAll<int8_t>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAll<int16_t>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAll<int64_t>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAllParallel<int32_t>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAllParallel<float>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAllParallel<double>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAllParallel<int8_t>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAllParallel<int16_t>(size_t, const ScanParams &);
template void MemoryScanner::snapshotAllParallel<int64_t>(size_t, const ScanParams &);

template void MemoryScanner::rescan<int32_t>(const ScanParams &, const int32_t *, const int32_t *);
template void MemoryScanner::rescan<float>(const ScanParams &, const float *, const float *);
template void MemoryScanner::rescan<double>(const ScanParams &, const double *, const double *);
template void MemoryScanner::rescan<int8_t>(const ScanParams &, const int8_t *, const int8_t *);
template void MemoryScanner::rescan<int16_t>(const ScanParams &, const int16_t *, const int16_t *);
template void MemoryScanner::rescan<int64_t>(const ScanParams &, const int64_t *, const int64_t *);

template void MemoryScanner::rescanShadow<int32_t>(const ScanParams &, const int32_t *, const int32_t *);
template void MemoryScanner::rescanShadow<float>(const ScanParams &, const float *, const float *);
template void MemoryScanner::rescanShadow<double>(const ScanParams &, const double *, const double *);
template void MemoryScanner::rescanShadow<int8_t>(const ScanParams &, const int8_t *, const int8_t *);
template void MemoryScanner::rescanShadow<int16_t>(const ScanParams &, const int16_t *, const int16_t *);
template void MemoryScanner::rescanShadow<int64_t>(const ScanParams &, const int64_t *, const int64_t *);

template uint64_t MemoryScanner::packRaw<int32_t>(const int32_t &) const;
template uint64_t MemoryScanner::packRaw<int16_t>(const int16_t &) const;
template uint64_t MemoryScanner::packRaw<int8_t>(const int8_t &) const;
template uint64_t MemoryScanner::packRaw<int64_t>(const int64_t &) const;
template uint64_t MemoryScanner::packRaw<float>(const float &) const;
template uint64_t MemoryScanner::packRaw<double>(const double &) const;

bool MemoryScanner::passesRegionFilter(const ScanParams &params, const MemoryRegion &region) const {
    if (region.perms.find('r') == std::string::npos) return false;
    if (params.requireWritable && region.perms.find('w') == std::string::npos) return false;
    if (params.requireExecutable && region.perms.find('x') == std::string::npos) return false;
    if (params.skipMaskedRegions && isMaskedRegion(region)) return false;
    return true;
}

std::pair<uintptr_t, uintptr_t> MemoryScanner::clampRange(const ScanParams &params, const MemoryRegion &region) const {
    uintptr_t start = region.start;
    uintptr_t end = region.end;
    if (params.startAddress) start = std::max(start, params.startAddress);
    if (params.endAddress) end = std::min(end, params.endAddress);
    return {start, end};
}

bool MemoryScanner::isMaskedRegion(const MemoryRegion &region) const {
    if (region.path.empty()) return false;
    static const char *kMasked[] = {"[vvar]", "[vdso]", "[vsyscall]", "linux-vdso", "linux-gate", "[vectors]"};
    for (const char *mask : kMasked) {
        if (region.path.find(mask) != std::string::npos) return true;
    }
    return false;
}

void MemoryScanner::scanArrayOfByte(const ScanParams &params) {
    std::vector<int> pattern;
    if (!parseAobPattern(params.value1, pattern)) return;
    results_.clear();
    constexpr size_t kChunk = 1024 * 1024;
    constexpr size_t kMaxResults = 20000000;
    std::vector<unsigned char> buffer(kChunk + 32); // extra for overlap
    for (const auto &region : proc_.regions()) {
        if (cancel_.load(std::memory_order_relaxed) || results_.size() >= kMaxResults) return;
        if (!passesRegionFilter(params, region)) continue;
        auto [start, end] = clampRange(params, region);
        if (end <= start) continue;
        for (uintptr_t addr = start; addr < end; addr += kChunk) {
            if (cancel_.load(std::memory_order_relaxed) || results_.size() >= kMaxResults) return;
            size_t toRead = std::min(kChunk, end - addr);
            if (buffer.size() < toRead + pattern.size()) buffer.resize(toRead + pattern.size());
            
            if (!proc_.readMemory(addr, buffer.data(), toRead)) continue;
            progressAdd(toRead);
            size_t limit = toRead >= pattern.size() ? toRead - pattern.size() + 1 : 0;
            
            // This loop is harder to auto-vectorize due to the pattern mask,
            // but removing the atomic check helps.
            for (size_t i = 0; i < limit; ++i) {
                bool match = true;
                for (size_t j = 0; j < pattern.size(); ++j) {
                    int p = pattern[j];
                    if (p == -1) continue;
                    if (buffer[i + j] != static_cast<unsigned char>(p)) { match = false; break; }
                }
                if (match) {
                    if (results_.size() < kMaxResults) {
                        results_.push_back(ScanResult{addr + i, 0});
                    } else {
                        return;
                    }
                }
            }
        }
    }
}

void MemoryScanner::scanString(const ScanParams &params) {
    const std::string &needle = params.value1;
    if (needle.empty()) return;
    results_.clear();
    constexpr size_t kChunk = 1024 * 1024;
    constexpr size_t kMaxResults = 20000000;
    std::vector<unsigned char> buffer(kChunk);
    for (const auto &region : proc_.regions()) {
        if (cancel_.load(std::memory_order_relaxed) || results_.size() >= kMaxResults) return;
        if (!passesRegionFilter(params, region)) continue;
        auto [start, end] = clampRange(params, region);
        if (end <= start) continue;
        for (uintptr_t addr = start; addr < end; addr += kChunk) {
            if (cancel_.load(std::memory_order_relaxed) || results_.size() >= kMaxResults) return;
            size_t toRead = std::min(kChunk, end - addr);
            if (buffer.size() < toRead) buffer.resize(toRead);
            
            if (!proc_.readMemory(addr, buffer.data(), toRead)) continue;
            progressAdd(toRead);
            auto begin = reinterpret_cast<const char *>(buffer.data());
            auto it = std::search(begin, begin + toRead, needle.begin(), needle.end());
            while (it != begin + toRead) {
                if (results_.size() >= kMaxResults) return;
                uintptr_t found = addr + static_cast<size_t>(it - begin);
                results_.push_back(ScanResult{found, 0});
                it = std::search(it + 1, begin + toRead, needle.begin(), needle.end());
            }
        }
    }
}

void MemoryScanner::cleanupShadowFile() {
    if (shadowMap_ && shadowMap_ != MAP_FAILED) {
        munmap(shadowMap_, shadowMapSize_);
        shadowMap_ = nullptr;
        shadowMapSize_ = 0;
    }
    if (shadowFd_ != -1) {
        close(shadowFd_);
        shadowFd_ = -1;
    }
    if (!shadowFilePath_.empty()) {
        std::remove(shadowFilePath_.c_str());
        shadowFilePath_.clear();
    }
}

void MemoryScanner::createShadowCopy(const ScanParams &params) {
    shadowRegions_.clear();
    cleanupShadowFile();
    
    char tmppath[] = "/tmp/comfy_shadow_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd == -1) return;
    shadowFilePath_ = tmppath;
    shadowFd_ = fd;
    
    // We use a large buffer to minimize write() calls
    constexpr size_t kMaxBlock = 4 * 1024 * 1024;
    std::vector<unsigned char> buffer;
    buffer.reserve(kMaxBlock);

    uint64_t currentFileOffset = 0;
    auto regions = proc_.regions();

    for (const auto &region : regions) {
        if (cancel_.load(std::memory_order_relaxed)) break;
        if (!passesRegionFilter(params, region)) continue;
        auto [start, end] = clampRange(params, region);
        if (end <= start) continue;

        for (uintptr_t addr = start; addr < end; addr += kMaxBlock) {
            if (cancel_.load(std::memory_order_relaxed)) break;
            size_t toRead = std::min(kMaxBlock, end - addr);
            buffer.resize(toRead);
            
            if (proc_.readMemory(addr, buffer.data(), toRead)) {
                 if (write(shadowFd_, buffer.data(), toRead) != static_cast<ssize_t>(toRead)) break;
                 
                 MemoryRegionSnapshot snap;
                 snap.start = addr;
                 snap.size = toRead;
                 snap.fileOffset = currentFileOffset;
                 shadowRegions_.push_back(snap);
                 
                 currentFileOffset += toRead;
                 progressAdd(toRead);
            }
        }
    }
    
    if (currentFileOffset > 0) {
        shadowMapSize_ = currentFileOffset;
        shadowMap_ = mmap(nullptr, shadowMapSize_, PROT_READ, MAP_PRIVATE, shadowFd_, 0);
        if (shadowMap_ == MAP_FAILED) {
            shadowMap_ = nullptr;
            shadowMapSize_ = 0;
        } else {
            // Advise the kernel that we will read this sequentially during rescan
            madvise(shadowMap_, shadowMapSize_, MADV_SEQUENTIAL);
        }
    }
}

template <typename T>
void MemoryScanner::rescanShadow(const ScanParams &params, const T *needle, const T *needle2) {
    results_.clear();
    constexpr size_t kMaxResults = 20000000;
    
    size_t workerCount = std::max<size_t>(1, std::thread::hardware_concurrency());
    std::mutex mtx;
    std::vector<std::thread> threads;
    std::atomic<bool> limitReached{false};
    
    // Ensure file exists
    if (shadowFilePath_.empty()) return;

    threads.reserve(workerCount);
    for (size_t t = 0; t < workerCount; ++t) {
        threads.emplace_back([&, t]() {
            std::vector<unsigned char> currentBuffer;
            std::vector<unsigned char> shadowBuffer;
            std::vector<ScanResult> local;
            local.reserve(4096);
            
            // Open a per-thread file handle for thread-safe seeking
            std::ifstream shadowFile(shadowFilePath_, std::ios::binary);
            if (!shadowFile) return;

            for (size_t ri = t; ri < shadowRegions_.size(); ri += workerCount) {
                if (cancel_.load(std::memory_order_relaxed) || limitReached.load(std::memory_order_relaxed)) break;
                
                const auto &snap = shadowRegions_[ri];
                size_t regionSize = snap.size;
                if (currentBuffer.size() < regionSize) currentBuffer.resize(regionSize);
                if (shadowBuffer.size() < regionSize) shadowBuffer.resize(regionSize);
                
                // Read current memory
                if (!proc_.readMemory(snap.start, currentBuffer.data(), regionSize)) continue;
                
                // Read shadow memory from file
                shadowFile.seekg(snap.fileOffset);
                if (!shadowFile.read(reinterpret_cast<char*>(shadowBuffer.data()), regionSize)) continue;

                progressAdd(regionSize);

                for (size_t offset = 0; offset + sizeof(T) <= regionSize; offset += params.alignment) {
                    if (cancel_.load(std::memory_order_relaxed)) break;
                    
                    T currentValue;
                    T oldValue;
                    std::memcpy(&currentValue, currentBuffer.data() + offset, sizeof(T));
                    std::memcpy(&oldValue, shadowBuffer.data() + offset, sizeof(T));
                    
                    bool keep = false;
                    switch (params.mode) {
                        case ScanMode::Changed:
                            keep = (currentValue != oldValue);
                            break;
                        case ScanMode::Unchanged:
                            keep = (currentValue == oldValue);
                            break;
                        case ScanMode::Increased:
                            keep = (currentValue > oldValue);
                            break;
                        case ScanMode::Decreased:
                            keep = (currentValue < oldValue);
                            break;
                         case ScanMode::Exact:
                            keep = (needle && currentValue == *needle);
                            break;
                        case ScanMode::GreaterThan:
                            keep = (needle && currentValue > *needle);
                            break;
                        case ScanMode::LessThan:
                            keep = (needle && currentValue < *needle);
                            break;
                        case ScanMode::Between:
                            keep = (needle && needle2 && currentValue >= *needle && currentValue <= *needle2);
                            break;
                        default:
                            break;
                    }
                    
                    if (keep) {
                        local.push_back(ScanResult{snap.start + offset, packRaw(currentValue)});
                    }
                    
                    if (local.size() >= 10000) {
                        std::lock_guard<std::mutex> lock(mtx);
                        if (results_.size() + local.size() > kMaxResults) {
                            limitReached.store(true, std::memory_order_relaxed);
                        } else {
                            results_.insert(results_.end(), local.begin(), local.end());
                        }
                        local.clear();
                    }
                }
            }
            if (!local.empty()) {
                std::lock_guard<std::mutex> lock(mtx);
                if (results_.size() + local.size() <= kMaxResults) {
                    results_.insert(results_.end(), local.begin(), local.end());
                } else {
                    limitReached.store(true, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto &th : threads) th.join();
    
    // We clean up the file only when we are done or resetting.
    // However, if we found results, we might not need the shadow anymore?
    // Actually, user might want to undo or do another scan against the SAME base.
    // So keep it.
}

} // namespace core
