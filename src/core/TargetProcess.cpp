#include "core/TargetProcess.h"
#include "core/DebugWatch.h"

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <string>

namespace {
class PtraceGuard {
public:
    explicit PtraceGuard(pid_t pid) : pid_(pid) {
        if (pid_ <= 0) return;
        if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) == -1) {
            return;
        }
        int status = 0;
        if (waitpid(pid_, &status, __WALL) == -1) {
            ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
            return;
        }
        attached_ = true;
    }
    ~PtraceGuard() {
        if (attached_) {
            ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        }
    }
    bool ok() const { return attached_; }

private:
    pid_t pid_{-1};
    bool attached_{false};
};
} // namespace

#include <sys/user.h>
#include <sys/mman.h>

namespace {
// Helper for ptrace-based syscall injection
struct RemoteCallContext {
    pid_t pid;
    struct user_regs_struct oldRegs;
    uint8_t oldCode[8];
    uintptr_t rip;
    bool active{false};

    RemoteCallContext(pid_t p) : pid(p) {
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) return;
        int status;
        waitpid(pid, &status, __WALL);
        
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) == -1) return;
        rip = oldRegs.rip;

        // Backup 2 bytes for 'syscall' (0x0F 0x05)
        for (int i = 0; i < 8; ++i) {
            long word = ptrace(PTRACE_PEEKDATA, pid, rip + i, nullptr);
            oldCode[i] = static_cast<uint8_t>(word & 0xFF);
        }
        active = true;
    }

    ~RemoteCallContext() {
        if (!active) return;
        // Restore code
        for (int i = 0; i < 8; ++i) {
            long word = ptrace(PTRACE_PEEKDATA, pid, rip + i, nullptr);
            word = (word & ~0xFFL) | oldCode[i];
            ptrace(PTRACE_POKEDATA, pid, rip + i, word);
        }
        // Restore regs
        ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    }
};
} // namespace

namespace core {

TargetProcess::TargetProcess() = default;

TargetProcess::~TargetProcess() {
    detach();
}

bool TargetProcess::attach(pid_t pid) {
    lastError_.clear();
    if (attached_ && pid_ == pid) return true;
    if (attached_) detach();
    pid_ = pid;
    return attach();
}

bool TargetProcess::attach() {
    lastError_.clear();
    if (attached_) return true;
    if (pid_ <= 0) {
        lastError_ = "invalid pid";
        return false;
    }
    // With ptrace_scope=0 we can read/write using process_vm_* without
    // taking a global ptrace attachment. Keep this lightweight here;
    // debug features that need ptrace (like hardware watchpoints) manage
    // their own attachments.
    attached_ = true;
    return true;
}

void TargetProcess::detach() {
    if (!attached_) return;
    attached_ = false;
    pid_ = -1;
    lastError_.clear();
}

std::vector<MemoryRegion> TargetProcess::regions() const {
    std::vector<MemoryRegion> out;
    if (!attached_) return out;
    std::stringstream path;
    path << "/proc/" << pid_ << "/maps";
    std::ifstream f(path.str());
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string range, perms, offset, dev, inode, pathName;
        if (!(iss >> range >> perms >> offset >> dev >> inode)) continue;
        std::getline(iss, pathName);
        if (!pathName.empty() && pathName[0] == ' ') pathName.erase(0, 1);
        auto dash = range.find('-');
        if (dash == std::string::npos) continue;
        uintptr_t start = std::stoull(range.substr(0, dash), nullptr, 16);
        uintptr_t end = std::stoull(range.substr(dash + 1), nullptr, 16);
        out.push_back(MemoryRegion{start, end, perms, pathName});
    }
    return out;
}

std::vector<pid_t> TargetProcess::listThreads() const {
    std::vector<pid_t> tids;
    if (!attached_) return tids;
    std::string taskDir = "/proc/" + std::to_string(pid_) + "/task";
    if (DIR *dir = opendir(taskDir.c_str())) {
        while (auto *ent = readdir(dir)) {
            if (ent->d_name[0] == '.') continue;
            pid_t tid = static_cast<pid_t>(std::strtol(ent->d_name, nullptr, 10));
            if (tid > 0) tids.push_back(tid);
        }
        closedir(dir);
    }
    return tids;
}

bool TargetProcess::readMemory(uintptr_t address, void *buffer, size_t len) const {
    if (!attached_) return false;
    struct iovec local{buffer, len};
    struct iovec remote{reinterpret_cast<void *>(address), len};
    ssize_t n = process_vm_readv(pid_, &local, 1, &remote, 1, 0);
    if (n == static_cast<ssize_t>(len)) return true;
    // Fallback to ptrace for small reads
    PtraceGuard guard(pid_);
    if (!guard.ok()) return false;
    size_t readBytes = 0;
    long word = 0;
    unsigned char *buf = static_cast<unsigned char *>(buffer);
    errno = 0;
    while (readBytes < len) {
        word = ptrace(PTRACE_PEEKDATA, pid_, address + readBytes, nullptr);
        if (word == -1 && errno) return false;
        size_t copy = std::min(sizeof(long), len - readBytes);
        std::memcpy(buf + readBytes, &word, copy);
        readBytes += copy;
    }
    return true;
}

bool TargetProcess::writeMemory(uintptr_t address, const void *buffer, size_t len) const {
    if (!attached_) return false;
    struct iovec local{const_cast<void *>(buffer), len};
    struct iovec remote{reinterpret_cast<void *>(address), len};
    ssize_t n = process_vm_writev(pid_, &local, 1, &remote, 1, 0);
    if (n == static_cast<ssize_t>(len)) return true;
    // Fallback to ptrace for small writes
    PtraceGuard guard(pid_);
    if (!guard.ok()) {
        if (DebugWatchSession::writeViaWatcher(pid_, address,
                                               static_cast<const uint8_t *>(buffer), len)) {
            return true;
        }
        return false;
    }
    size_t written = 0;
    const unsigned char *buf = static_cast<const unsigned char *>(buffer);
    while (written < len) {
        long word = ptrace(PTRACE_PEEKDATA, pid_, address + written, nullptr);
        size_t copy = std::min(sizeof(long), len - written);
        std::memcpy(&word, buf + written, copy);
        if (ptrace(PTRACE_POKEDATA, pid_, address + written, word) == -1) {
            return false;
        }
        written += copy;
    }
    return true;
}

uintptr_t TargetProcess::allocateMemory(size_t size, int prot) {
    RemoteCallContext ctx(pid_);
    if (!ctx.active) return 0;

    // syscall 9: mmap(addr, len, prot, flags, fd, off)
    struct user_regs_struct regs = ctx.oldRegs;
    regs.rax = 9;             // mmap
    regs.rdi = 0;             // addr
    regs.rsi = size;          // len
    regs.rdx = prot;          // prot
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; // flags
    regs.r8  = -1;            // fd
    regs.r9  = 0;             // off

    // Inject syscall instruction
    long syscall_instr = 0x050F; // 0F 05
    long original = ptrace(PTRACE_PEEKDATA, pid_, ctx.rip, nullptr);
    ptrace(PTRACE_POKEDATA, pid_, ctx.rip, (original & ~0xFFFFL) | syscall_instr);

    if (ptrace(PTRACE_SETREGS, pid_, nullptr, &regs) == -1) return 0;
    if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) == -1) return 0;
    
    int status;
    waitpid(pid_, &status, __WALL);

    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) == -1) return 0;
    
    // Result is in RAX. If it's > -4096, it's an error code.
    if (regs.rax > (unsigned long)-4096) return 0;

    return static_cast<uintptr_t>(regs.rax);
}

bool TargetProcess::freeMemory(uintptr_t address, size_t size) {
    RemoteCallContext ctx(pid_);
    if (!ctx.active) return false;

    // syscall 11: munmap(addr, len)
    struct user_regs_struct regs = ctx.oldRegs;
    regs.rax = 11;
    regs.rdi = address;
    regs.rsi = size;

    long syscall_instr = 0x050F;
    long original = ptrace(PTRACE_PEEKDATA, pid_, ctx.rip, nullptr);
    ptrace(PTRACE_POKEDATA, pid_, ctx.rip, (original & ~0xFFFFL) | syscall_instr);

    if (ptrace(PTRACE_SETREGS, pid_, nullptr, &regs) == -1) return false;
    if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) == -1) return false;
    
    int status;
    waitpid(pid_, &status, __WALL);

    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) == -1) return false;
    return regs.rax == 0;
}

bool TargetProcess::setExecutionPointer(uintptr_t ip) {
    PtraceGuard guard(pid_);
    if (!guard.ok()) return false;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) == -1) return false;
    regs.rip = ip;
    return ptrace(PTRACE_SETREGS, pid_, nullptr, &regs) != -1;
}

uintptr_t TargetProcess::getExecutionPointer() const {
    PtraceGuard guard(pid_);
    if (!guard.ok()) return 0;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) == -1) return 0;
    return regs.rip;
}

uint64_t TargetProcess::remoteCall(uintptr_t address, uint64_t rdi, uint64_t rsi) {
    RemoteCallContext ctx(pid_);
    if (!ctx.active) return 0;

    struct user_regs_struct regs = ctx.oldRegs;
    regs.rip = address;
    regs.rdi = rdi;
    regs.rsi = rsi;
    
    // We need to stop the execution when it returns.
    // A common trick is to push a 'trap' address onto the stack.
    // Or simpler: put an INT3 (0xCC) at the current RIP and set return address to current RIP.
    // But RemoteCallContext already backs up 8 bytes at current RIP.
    
    uint8_t int3 = 0xCC;
    long original = ptrace(PTRACE_PEEKDATA, pid_, ctx.rip, nullptr);
    ptrace(PTRACE_POKEDATA, pid_, ctx.rip, (original & ~0xFFL) | int3);

    // Set return address to the INT3
    regs.rsp -= 8;
    ptrace(PTRACE_POKEDATA, pid_, regs.rsp, ctx.rip);

    if (ptrace(PTRACE_SETREGS, pid_, nullptr, &regs) == -1) return 0;
    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) == -1) return 0;

    int status;
    waitpid(pid_, &status, __WALL);

    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) == -1) return 0;
    return regs.rax;
}

} // namespace core
