#pragma once

#include <vector>
#include <string>
#include <sys/types.h>
#include <cstdint>

namespace core {

struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
    std::string perms; // e.g. r-xp
    std::string path;
};

class TargetProcess {
public:
    TargetProcess();
    ~TargetProcess();

    bool attach(pid_t pid);
    bool attach(); // uses existing pid_
    void detach();

    bool isAttached() const { return attached_; }
    pid_t pid() const { return pid_; }
    const std::string &lastError() const { return lastError_; }

    std::vector<MemoryRegion> regions() const;
    std::vector<pid_t> listThreads() const;

    bool readMemory(uintptr_t address, void *buffer, size_t len) const;
    bool writeMemory(uintptr_t address, const void *buffer, size_t len) const;

    // Remote Allocation & Control
    uintptr_t allocateMemory(size_t size, int prot = 7 /* PROT_READ|WRITE|EXEC */);
    bool freeMemory(uintptr_t address, size_t size);

    // Low-level ptrace helpers
    bool setExecutionPointer(uintptr_t ip);
    uintptr_t getExecutionPointer() const;
    uint64_t remoteCall(uintptr_t address, uint64_t rdi = 0, uint64_t rsi = 0);

private:
    bool attached_{false};
    pid_t pid_{-1};
    std::string lastError_;
};

} // namespace core
