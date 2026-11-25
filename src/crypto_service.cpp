#include "crypto_service.h"

#include "byte_stream.h"

#include <algorithm>
#include <stdexcept>
#include <string>

namespace cryptotool {

namespace {

std::string status_message(int status, const AlgorithmModule& module) {
    const std::string algorithm = module.info->algorithm_name;
    switch (status) {
    case CRYPTO_STATUS_INVALID_KEY:
        return "Ключ не подходит для алгоритма " + algorithm + ": неверная длина или содержимое ключа.";
    case CRYPTO_STATUS_INVALID_INPUT:
        return "Не удалось расшифровать данные алгоритмом " + algorithm +
               ": шифротекст повреждён или создан другим ключом.";
    case CRYPTO_STATUS_OUTPUT_TOO_SMALL:
        return "Библиотека " + algorithm + " сообщила о нехватке выходного буфера.";
    case CRYPTO_STATUS_RANDOM_FAILURE:
        return "Ошибка криптостойкого генератора случайных чисел.";
    case CRYPTO_STATUS_INVALID_ARGUMENT:
        return "Библиотека " + algorithm + " получила неверные параметры вызова.";
    default:
        return "Внутренняя ошибка библиотеки " + algorithm + " (код " + std::to_string(status) + ").";
    }
}

void require_success(int status, const AlgorithmModule& module) {
    if (status != CRYPTO_STATUS_OK) throw std::runtime_error(status_message(status, module));
}

void write_to_all(const std::vector<std::ostream*>& outputs, const SecureBytes& bytes) {
    std::for_each(outputs.begin(), outputs.end(),
                  [&bytes](std::ostream* output) { write_bytes(*output, bytes.data(), bytes.size()); });
}

void fill_with_random_key(const AlgorithmModule& module, SecureBytes& key) {
    MutBuffer key_buffer{key.data(), key.size()};
    require_success(module.generate_key(&key_buffer), module);
}

void read_keystream_slice(std::istream& keystream, SecureBytes& key_slice) {
    const std::size_t received = read_bytes(keystream, key_slice.data(), key_slice.size());
    if (received != key_slice.size()) throw std::runtime_error("Ключ короче данных: для шифра Вернама длины должны совпадать.");
}

ConstBuffer key_for_chunk(const AlgorithmModule& module, KeyMaterial& key, SecureBytes& key_slice, std::size_t chunk_size) {
    if (!uses_keystream(module)) return ConstBuffer{key.fixed_key.data(), key.fixed_key.size()};
    key_slice.resize(chunk_size);
    if (key.generate_keystream) {
        fill_with_random_key(module, key_slice);
        write_to_all(key.generated_key_outputs, key_slice);
    } else {
        read_keystream_slice(*key.keystream_input, key_slice);
    }
    return ConstBuffer{key_slice.data(), key_slice.size()};
}

std::size_t input_chunk_size(const AlgorithmModule& module, Operation operation) {
    if (operation == Operation::ENCRYPT) return DATA_CHUNK_SIZE;
    const std::size_t encrypted_chunk_size = module.get_output_size(DATA_CHUNK_SIZE, CRYPTO_OPERATION_ENCRYPT);
    if (encrypted_chunk_size == 0) throw std::runtime_error("Библиотека вернула нулевой размер блока данных.");
    return encrypted_chunk_size;
}

}

bool uses_keystream(const AlgorithmModule& module) {
    return module.info->key_follows_data_length != 0;
}

SecureBytes generate_fixed_key(const AlgorithmModule& module, std::size_t key_size) {
    SecureBytes key(key_size);
    fill_with_random_key(module, key);
    return key;
}

void generate_keystream(const AlgorithmModule& module, std::size_t key_size, const std::vector<std::ostream*>& outputs) {
    SecureBytes key_slice;
    for (std::size_t generated = 0; generated < key_size;) {
        key_slice.resize(std::min(DATA_CHUNK_SIZE, key_size - generated));
        fill_with_random_key(module, key_slice);
        write_to_all(outputs, key_slice);
        generated += key_slice.size();
    }
}

void transform_stream(const AlgorithmModule& module, Operation operation, KeyMaterial& key, std::istream& input,
                      std::ostream& output) {
    const CryptFunction crypt = operation == Operation::ENCRYPT ? module.encrypt : module.decrypt;
    const int operation_type = operation == Operation::ENCRYPT ? CRYPTO_OPERATION_ENCRYPT : CRYPTO_OPERATION_DECRYPT;
    const std::size_t chunk_capacity = input_chunk_size(module, operation);

    SecureBytes input_chunk(chunk_capacity);
    SecureBytes output_chunk;
    SecureBytes key_slice;
    for (std::size_t processed_chunks = 0;; ++processed_chunks) {
        const std::size_t chunk_size = read_bytes(input, input_chunk.data(), chunk_capacity);
        if (chunk_size == 0 && processed_chunks > 0) break;

        const ConstBuffer chunk_key = key_for_chunk(module, key, key_slice, chunk_size);
        output_chunk.resize(module.get_output_size(chunk_size, operation_type));
        MutBuffer output_buffer{output_chunk.data(), output_chunk.size()};
        require_success(crypt(chunk_key, ConstBuffer{input_chunk.data(), chunk_size}, &output_buffer), module);
        write_bytes(output, output_chunk.data(), output_buffer.size);

        if (chunk_size < chunk_capacity) break;
    }

    if (key.keystream_input != nullptr && has_more_bytes(*key.keystream_input)) {
        throw std::runtime_error("Ключ длиннее данных: для шифра Вернама длины должны совпадать.");
    }
}

}
