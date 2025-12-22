#include "core/CodeInjector.h"

#include <algorithm>
#include <cstring>

#include <capstone/capstone.h>
#include <sys/user.h>

namespace core {

CodeInjector::CodeInjector(const TargetProcess &proc) : proc_(proc) {}

bool CodeInjector::patchBytes(uintptr_t address, const std::vector<uint8_t> &bytes) {
    if (!proc_.isAttached()) return false;
    PatchRecord rec{};
    rec.address = address;
    rec.patched = bytes;
    rec.original.resize(bytes.size());
    if (!proc_.readMemory(address, rec.original.data(), rec.original.size())) return false;
    if (!proc_.writeMemory(address, rec.patched.data(), rec.patched.size())) return false;
    patches_[address] = rec;
    return true;
}

bool CodeInjector::safePatch(uintptr_t address, const std::vector<uint8_t> &bytes, bool nopFill) {
    if (!proc_.isAttached()) return false;

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return false;

    std::vector<uint8_t> buffer(bytes.size() + 16);
    if (!proc_.readMemory(address, buffer.data(), buffer.size())) {
        cs_close(&handle);
        return false;
    }

    cs_insn *insn;
    size_t count = cs_disasm(handle, buffer.data(), buffer.size(), address, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        return false;
    }

    size_t bytesToOverwrite = 0;
    for (size_t i = 0; i < count; ++i) {
        bytesToOverwrite += insn[i].size;
        if (bytesToOverwrite >= bytes.size()) break;
    }
    cs_free(insn, count);
    cs_close(&handle);

    if (bytesToOverwrite < bytes.size()) return false;

    std::vector<uint8_t> finalPatch = bytes;
    if (nopFill && bytesToOverwrite > bytes.size()) {
        finalPatch.resize(bytesToOverwrite, 0x90);
    }

    return patchBytes(address, finalPatch);
}

bool CodeInjector::restore(uintptr_t address) {
    auto it = patches_.find(address);
    if (it == patches_.end()) return false;
    if (!proc_.writeMemory(address, it->second.original.data(), it->second.original.size())) return false;
    patches_.erase(it);
    return true;
}

uintptr_t CodeInjector::allocateRemote(size_t size) {
    return const_cast<TargetProcess&>(proc_).allocateMemory(size);
}

bool CodeInjector::injectJmp(uintptr_t at, uintptr_t to) {
    int64_t offset = static_cast<int64_t>(to) - (static_cast<int64_t>(at) + 5);
    
    if (offset < -2147483648LL || offset > 2147483647LL) {
        std::vector<uint8_t> absJmp = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
        absJmp.resize(14);
        std::memcpy(absJmp.data() + 6, &to, sizeof(to));
        return safePatch(at, absJmp);
    }

    std::vector<uint8_t> relJmp = {0xE9, 0, 0, 0, 0};
    int32_t offset32 = static_cast<int32_t>(offset);
    std::memcpy(relJmp.data() + 1, &offset32, 4);
    return safePatch(at, relJmp);
}

uint64_t CodeInjector::remoteCall(uintptr_t address, uint64_t rdi, uint64_t rsi) {
    return const_cast<TargetProcess&>(proc_).remoteCall(address, rdi, rsi);
}

} // namespace core
