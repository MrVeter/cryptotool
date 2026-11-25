#include "crypto_plugin_api.h"
#include "plugin_support.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <numeric>
#include <vector>

namespace table_transposition {

using plugin_support::require;

constexpr size_t MIN_COLUMNS = 2;
constexpr size_t MAX_COLUMNS = 255;
constexpr size_t DEFAULT_COLUMNS = 16;

const AlgorithmInfo ALGORITHM_INFO{"table", DEFAULT_COLUMNS, 0};

// Key byte j is the label of column j; columns are read in ascending label order (labels 1..N, each once).
std::vector<size_t> column_reading_order(ConstBuffer key) {
    require(key.data != nullptr && key.size >= MIN_COLUMNS && key.size <= MAX_COLUMNS, CRYPTO_STATUS_INVALID_KEY);
    std::vector<size_t> reading_order(key.size, key.size);
    for (size_t column = 0; column < key.size; ++column) {
        const size_t label = key.data[column];
        require(label >= 1 && label <= key.size && reading_order[label - 1] == key.size, CRYPTO_STATUS_INVALID_KEY);
        reading_order[label - 1] = column;
    }
    return reading_order;
}

// Position k of the ciphertext takes the byte at source_positions[k] of the plaintext; the last row may be partial.
std::vector<size_t> source_positions(ConstBuffer key, size_t data_size) {
    const std::vector<size_t> reading_order = column_reading_order(key);
    const size_t column_count = reading_order.size();
    std::vector<size_t> positions;
    positions.reserve(data_size);
    for (size_t column : reading_order) {
        for (size_t position = column; position < data_size; position += column_count) {
            positions.push_back(position);
        }
    }
    return positions;
}

void transpose(ConstBuffer key, ConstBuffer input, MutBuffer* output, int operation_type) {
    plugin_support::require_input(input);
    plugin_support::require_output(output, input.size);
    std::vector<size_t> positions = source_positions(key, input.size);
    if (operation_type == CRYPTO_OPERATION_ENCRYPT) {
        std::transform(positions.begin(), positions.end(), output->data,
                       [&input](size_t position) { return input.data[position]; });
    } else {
        auto cipher_byte = input.data;
        std::for_each(positions.begin(), positions.end(),
                      [&output, &cipher_byte](size_t position) { output->data[position] = *cipher_byte++; });
    }
    output->size = input.size;
    OPENSSL_cleanse(positions.data(), positions.size() * sizeof(size_t));
}

size_t random_index_below(size_t bound) {
    const uint32_t limit = static_cast<uint32_t>(bound);
    const uint32_t rejection_threshold = static_cast<uint32_t>(0u - limit) % limit;
    uint32_t value = 0;
    do {
        require(RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) == 1,
                CRYPTO_STATUS_RANDOM_FAILURE);
    } while (value < rejection_threshold);
    return value % limit;
}

void generate_permutation(MutBuffer* key) {
    require(key != nullptr && key->data != nullptr, CRYPTO_STATUS_INVALID_ARGUMENT);
    require(key->size >= MIN_COLUMNS && key->size <= MAX_COLUMNS, CRYPTO_STATUS_INVALID_KEY);
    uint8_t* labels_begin = key->data;
    uint8_t* labels_end = key->data + key->size;
    std::iota(labels_begin, labels_end, static_cast<uint8_t>(1));
    for (size_t index = key->size - 1; index > 0; --index) {
        std::iter_swap(labels_begin + index, labels_begin + random_index_below(index + 1));
    }
}

}

extern "C" {

CRYPTO_PLUGIN_EXPORT const AlgorithmInfo* get_algorithm_info(void) {
    return &table_transposition::ALGORITHM_INFO;
}

CRYPTO_PLUGIN_EXPORT size_t get_output_size(size_t input_size, int operation_type) {
    const bool known_operation = operation_type == CRYPTO_OPERATION_ENCRYPT || operation_type == CRYPTO_OPERATION_DECRYPT;
    return known_operation ? input_size : 0;
}

CRYPTO_PLUGIN_EXPORT int generate_key(MutBuffer* key) {
    return plugin_support::run_guarded([&] { table_transposition::generate_permutation(key); });
}

CRYPTO_PLUGIN_EXPORT int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return plugin_support::run_guarded(
        [&] { table_transposition::transpose(key, input, output, CRYPTO_OPERATION_ENCRYPT); });
}

CRYPTO_PLUGIN_EXPORT int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return plugin_support::run_guarded(
        [&] { table_transposition::transpose(key, input, output, CRYPTO_OPERATION_DECRYPT); });
}

}
