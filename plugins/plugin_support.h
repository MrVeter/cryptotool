#pragma once

#include "crypto_plugin_api.h"

#include <new>

namespace plugin_support {

struct StatusError {
    int status;
};

[[noreturn]] inline void fail(int status) {
    throw StatusError{status};
}

inline void require(bool condition, int status) {
    if (!condition) fail(status);
}

inline void require_output(const MutBuffer* output, size_t required_size) {
    require(output != nullptr, CRYPTO_STATUS_INVALID_ARGUMENT);
    require(output->data != nullptr || required_size == 0, CRYPTO_STATUS_INVALID_ARGUMENT);
    require(output->size >= required_size, CRYPTO_STATUS_OUTPUT_TOO_SMALL);
}

inline void require_input(ConstBuffer buffer) {
    require(buffer.data != nullptr || buffer.size == 0, CRYPTO_STATUS_INVALID_ARGUMENT);
}

// Exceptions must not cross the C ABI boundary, so every exported function runs its body here.
template <typename Body>
int run_guarded(Body&& body) noexcept {
    try {
        body();
        return CRYPTO_STATUS_OK;
    } catch (const StatusError& error) {
        return error.status;
    } catch (const std::bad_alloc&) {
        return CRYPTO_STATUS_INTERNAL_ERROR;
    } catch (...) {
        return CRYPTO_STATUS_INTERNAL_ERROR;
    }
}

}
