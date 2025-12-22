#pragma once

#include "core/TargetProcess.h"
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace core {

struct PatchRecord {
    uintptr_t address;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
};

class CodeInjector {
public:
    explicit CodeInjector(const TargetProcess &proc);

    bool patchBytes(uintptr_t address, const std::vector<uint8_t> &bytes);
    bool restore(uintptr_t address);

    // Advanced Injection
    bool safePatch(uintptr_t address, const std::vector<uint8_t> &bytes, bool nopFill = true);
    uintptr_t allocateRemote(size_t size);
    bool injectJmp(uintptr_t at, uintptr_t to);
    
    // Remote Execution
    uint64_t remoteCall(uintptr_t address, uint64_t rdi = 0, uint64_t rsi = 0);

    const std::unordered_map<uintptr_t, PatchRecord> &patches() const { return patches_; }
    const TargetProcess &target() const { return proc_; }

private:
    const TargetProcess &proc_;
    std::unordered_map<uintptr_t, PatchRecord> patches_;
};

} // namespace core
