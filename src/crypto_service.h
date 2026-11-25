#pragma once

#include "algorithm_module.h"
#include "secure_memory.h"

#include <cstddef>
#include <iosfwd>
#include <vector>

namespace cryptotool {

// Data is processed in chunks so memory use does not depend on the file size.
// Each chunk is passed to the library as an independent message.
constexpr std::size_t DATA_CHUNK_SIZE = std::size_t{1} << 20;

enum class Operation { ENCRYPT, DECRYPT };

struct KeyMaterial {
    SecureBytes fixed_key;
    std::istream* keystream_input = nullptr;
    bool generate_keystream = false;
    std::vector<std::ostream*> generated_key_outputs;
};

bool uses_keystream(const AlgorithmModule& module);
SecureBytes generate_fixed_key(const AlgorithmModule& module, std::size_t key_size);
void generate_keystream(const AlgorithmModule& module, std::size_t key_size, const std::vector<std::ostream*>& outputs);
void transform_stream(const AlgorithmModule& module, Operation operation, KeyMaterial& key, std::istream& input,
                      std::ostream& output);

}
