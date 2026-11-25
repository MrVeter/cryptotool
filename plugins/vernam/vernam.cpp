#include "crypto_plugin_api.h"
#include "plugin_support.h"

#include <openssl/rand.h>

#include <algorithm>
#include <climits>
#include <functional>

namespace vernam {

using plugin_support::require;

const AlgorithmInfo ALGORITHM_INFO{"vernam", 0, 1};

// One-time pad: c[i] = m[i] XOR k[i], the key is exactly as long as the data and is never repeated.
void apply_keystream(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    plugin_support::require_input(input);
    plugin_support::require_input(key);
    require(key.size == input.size, CRYPTO_STATUS_INVALID_KEY);
    plugin_support::require_output(output, input.size);
    std::transform(input.data, input.data + input.size, key.data, output->data, std::bit_xor<uint8_t>());
    output->size = input.size;
}

void generate_keystream(MutBuffer* key) {
    require(key != nullptr && (key->data != nullptr || key->size == 0), CRYPTO_STATUS_INVALID_ARGUMENT);
    size_t filled = 0;
    while (filled < key->size) {
        const size_t portion = std::min<size_t>(key->size - filled, INT_MAX);
        require(RAND_priv_bytes(key->data + filled, static_cast<int>(portion)) == 1, CRYPTO_STATUS_RANDOM_FAILURE);
        filled += portion;
    }
}

}

extern "C" {

CRYPTO_PLUGIN_EXPORT const AlgorithmInfo* get_algorithm_info(void) {
    return &vernam::ALGORITHM_INFO;
}

CRYPTO_PLUGIN_EXPORT size_t get_output_size(size_t input_size, int operation_type) {
    const bool known_operation = operation_type == CRYPTO_OPERATION_ENCRYPT || operation_type == CRYPTO_OPERATION_DECRYPT;
    return known_operation ? input_size : 0;
}

CRYPTO_PLUGIN_EXPORT int generate_key(MutBuffer* key) {
    return plugin_support::run_guarded([&] { vernam::generate_keystream(key); });
}

CRYPTO_PLUGIN_EXPORT int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return plugin_support::run_guarded([&] { vernam::apply_keystream(key, input, output); });
}

CRYPTO_PLUGIN_EXPORT int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return plugin_support::run_guarded([&] { vernam::apply_keystream(key, input, output); });
}

}
