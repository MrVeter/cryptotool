#pragma once

#include "platform.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

namespace cryptotool {

// Every buffer holding keys or data is wiped before its memory goes back to the heap,
// including the old storage released when a vector grows.
template <typename Value>
struct WipingAllocator {
    using value_type = Value;

    WipingAllocator() noexcept = default;
    template <typename Other>
    WipingAllocator(const WipingAllocator<Other>&) noexcept {}

    Value* allocate(std::size_t count) {
        return static_cast<Value*>(::operator new(count * sizeof(Value)));
    }

    void deallocate(Value* pointer, std::size_t count) noexcept {
        secure_wipe(pointer, count * sizeof(Value));
        ::operator delete(pointer);
    }
};

template <typename Left, typename Right>
bool operator==(const WipingAllocator<Left>&, const WipingAllocator<Right>&) noexcept {
    return true;
}

template <typename Left, typename Right>
bool operator!=(const WipingAllocator<Left>&, const WipingAllocator<Right>&) noexcept {
    return false;
}

using SecureBytes = std::vector<std::uint8_t, WipingAllocator<std::uint8_t>>;

}
