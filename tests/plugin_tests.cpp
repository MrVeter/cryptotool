#include "elgamal_test_key.h"
#include "platform.h"
#include "plugin_loader.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <numeric>
#include <array>
#include <random>
#include <string>
#include <vector>

namespace plugin_tests {

using Bytes = std::vector<uint8_t>;

constexpr uint32_t DATA_SEED = 20261111;
constexpr std::array<std::size_t, 6> ELGAMAL_BOUNDARY_SIZES{0, 1, 253, 254, 255, 508};

struct TestFailure {
    std::string message;
};

struct CryptResult {
    int status;
    Bytes output;
};

struct TestContext {
    std::filesystem::path library_directory;
};

struct TestCase {
    const char* name;
    void (*run)(const TestContext&);
};

void expect(bool condition, const std::string& message) {
    if (!condition) throw TestFailure{message};
}

std::unique_ptr<cryptotool::LoadedAlgorithm> load_module(const TestContext& context, const std::string& name) {
    return cryptotool::load_algorithm(*cryptotool::find_algorithm(name), context.library_directory);
}

Bytes bytes_from_text(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

Bytes bytes_from_hex(const std::string& hex) {
    Bytes bytes(hex.size() / 2);
    std::transform(bytes.begin(), bytes.end(), bytes.begin(), [&hex, index = std::size_t{0}](uint8_t) mutable {
        const auto value = static_cast<uint8_t>(std::stoul(hex.substr(index, 2), nullptr, 16));
        index += 2;
        return value;
    });
    return bytes;
}

Bytes random_bytes(std::size_t size, uint32_t seed) {
    std::mt19937 generator(seed);
    std::uniform_int_distribution<int> distribution(0, 255);
    Bytes bytes(size);
    std::generate(bytes.begin(), bytes.end(), [&] { return static_cast<uint8_t>(distribution(generator)); });
    return bytes;
}

Bytes random_permutation_key(std::size_t columns, uint32_t seed) {
    Bytes key(columns);
    std::iota(key.begin(), key.end(), static_cast<uint8_t>(1));
    std::shuffle(key.begin(), key.end(), std::mt19937(seed));
    return key;
}

ConstBuffer view(const Bytes& bytes) {
    return ConstBuffer{bytes.data(), bytes.size()};
}

CryptResult run_crypt(const cryptotool::LoadedAlgorithm& loaded, int operation_type, const Bytes& key,
                      const Bytes& input) {
    const cryptotool::AlgorithmModule& module = loaded.module;
    CryptResult result{CRYPTO_STATUS_OK, Bytes(module.get_output_size(input.size(), operation_type))};
    MutBuffer output{result.output.data(), result.output.size()};
    const CryptFunction crypt = operation_type == CRYPTO_OPERATION_ENCRYPT ? module.encrypt : module.decrypt;
    result.status = crypt(view(key), view(input), &output);
    result.output.resize(result.status == CRYPTO_STATUS_OK ? output.size : 0);
    return result;
}

CryptResult run_encrypt_with_nonce(const cryptotool::LoadedAlgorithm& loaded, const Bytes& key, const Bytes& input,
                                   const Bytes& nonce) {
    void* symbol = cryptotool::find_library_symbol(loaded.library, "encrypt_with_nonce");
    expect(symbol != nullptr, "библиотека не экспортирует encrypt_with_nonce");
    CryptWithNonceFunction encrypt_with_nonce = nullptr;
    std::memcpy(&encrypt_with_nonce, &symbol, sizeof(encrypt_with_nonce));

    CryptResult result{CRYPTO_STATUS_OK, Bytes(loaded.module.get_output_size(input.size(), CRYPTO_OPERATION_ENCRYPT))};
    MutBuffer output{result.output.data(), result.output.size()};
    result.status = encrypt_with_nonce(view(key), view(input), view(nonce), &output);
    result.output.resize(result.status == CRYPTO_STATUS_OK ? output.size : 0);
    return result;
}

void expect_round_trip(const cryptotool::LoadedAlgorithm& module, const Bytes& key, const Bytes& plaintext) {
    const CryptResult encrypted = run_crypt(module, CRYPTO_OPERATION_ENCRYPT, key, plaintext);
    expect(encrypted.status == CRYPTO_STATUS_OK, "шифрование вернуло код " + std::to_string(encrypted.status));
    const CryptResult decrypted = run_crypt(module, CRYPTO_OPERATION_DECRYPT, key, encrypted.output);
    expect(decrypted.status == CRYPTO_STATUS_OK, "расшифрование вернуло код " + std::to_string(decrypted.status));
    expect(decrypted.output == plaintext,
           "расшифрованные данные не совпали с исходными, длина " + std::to_string(plaintext.size()));
}

void table_known_answer(const TestContext& context) {
    const auto module = load_module(context, "table");
    const Bytes key{3, 1, 4, 2};
    const CryptResult encrypted = run_crypt(*module, CRYPTO_OPERATION_ENCRYPT, key, bytes_from_text("ABCDEFGHIJ"));
    expect(encrypted.output == bytes_from_text("BFJDHAEICG"), "ожидался шифротекст BFJDHAEICG");
    expect_round_trip(*module, key, bytes_from_text("ABCDEFGHIJ"));
}

void table_random_data(const TestContext& context) {
    const auto module = load_module(context, "table");
    expect_round_trip(*module, random_permutation_key(17, DATA_SEED), random_bytes(100003, DATA_SEED));
    expect_round_trip(*module, random_permutation_key(255, DATA_SEED + 1), random_bytes(65536, DATA_SEED + 1));
}

void table_short_and_empty_data(const TestContext& context) {
    const auto module = load_module(context, "table");
    const Bytes key = random_permutation_key(255, DATA_SEED + 2);
    expect_round_trip(*module, key, Bytes{});
    expect_round_trip(*module, key, bytes_from_text("Привет"));
}

void table_rejects_invalid_keys(const TestContext& context) {
    const auto module = load_module(context, "table");
    const Bytes data = bytes_from_text("data");
    expect(run_crypt(*module, CRYPTO_OPERATION_ENCRYPT, Bytes{1, 1, 2}, data).status == CRYPTO_STATUS_INVALID_KEY,
           "повтор метки столбца должен отклоняться");
    expect(run_crypt(*module, CRYPTO_OPERATION_ENCRYPT, Bytes{1, 3}, data).status == CRYPTO_STATUS_INVALID_KEY,
           "метка вне диапазона должна отклоняться");
    expect(run_crypt(*module, CRYPTO_OPERATION_ENCRYPT, Bytes{1}, data).status == CRYPTO_STATUS_INVALID_KEY,
           "ключ из одного столбца должен отклоняться");
}

void vernam_known_answer(const TestContext& context) {
    const auto module = load_module(context, "vernam");
    const CryptResult encrypted = run_crypt(*module, CRYPTO_OPERATION_ENCRYPT, Bytes{0x0F, 0xFF}, Bytes{0x41, 0x00});
    expect(encrypted.output == Bytes({0x4E, 0xFF}), "ожидался шифротекст 4E FF");
}

void vernam_random_data(const TestContext& context) {
    const auto module = load_module(context, "vernam");
    expect_round_trip(*module, random_bytes(100000, DATA_SEED + 3), random_bytes(100000, DATA_SEED + 4));
    expect_round_trip(*module, random_bytes(1, DATA_SEED + 5), random_bytes(1, DATA_SEED + 6));
}

void vernam_empty_data_and_length_mismatch(const TestContext& context) {
    const auto module = load_module(context, "vernam");
    expect_round_trip(*module, Bytes{}, Bytes{});
    expect(run_crypt(*module, CRYPTO_OPERATION_ENCRYPT, Bytes(3), Bytes(4)).status == CRYPTO_STATUS_INVALID_KEY,
           "короткий ключ должен отклоняться");
    expect(run_crypt(*module, CRYPTO_OPERATION_ENCRYPT, Bytes(5), Bytes(4)).status == CRYPTO_STATUS_INVALID_KEY,
           "длинный ключ должен отклоняться");
}

void elgamal_deterministic_encryption(const TestContext& context) {
    const auto module = load_module(context, "elgamal");
    const Bytes key = bytes_from_hex(ELGAMAL_TEST_KEY_PAIR_HEX);
    const Bytes plaintext = bytes_from_text("Проверка шифра Эль-Гамаля: English 0123456789 !@#$%^&*()");
    const Bytes nonce = random_bytes(40, DATA_SEED + 7);
    const CryptResult first = run_encrypt_with_nonce(*module, key, plaintext, nonce);
    const CryptResult second = run_encrypt_with_nonce(*module, key, plaintext, nonce);
    expect(first.status == CRYPTO_STATUS_OK, "шифрование с фиксированным nonce вернуло ошибку");
    expect(first.output == second.output, "одинаковый nonce должен давать одинаковый шифротекст");
    const CryptResult decrypted = run_crypt(*module, CRYPTO_OPERATION_DECRYPT, key, first.output);
    expect(decrypted.output == plaintext, "расшифрованный текст не совпал с исходным");
}

void elgamal_block_boundaries(const TestContext& context) {
    const auto module = load_module(context, "elgamal");
    const Bytes key = bytes_from_hex(ELGAMAL_TEST_KEY_PAIR_HEX);
    const Bytes nonce = random_bytes(40, DATA_SEED + 8);
    for (std::size_t size : ELGAMAL_BOUNDARY_SIZES) {
        const Bytes plaintext = random_bytes(size, DATA_SEED + static_cast<uint32_t>(size));
        const CryptResult encrypted = run_encrypt_with_nonce(*module, key, plaintext, nonce);
        expect(encrypted.output.size() == (size / 254 + 1) * 512, "неверная длина шифротекста с PKCS#7");
        const CryptResult decrypted = run_crypt(*module, CRYPTO_OPERATION_DECRYPT, key, encrypted.output);
        expect(decrypted.output == plaintext, "ошибка на границе блока, длина " + std::to_string(size));
    }
}

void elgamal_random_data(const TestContext& context) {
    const auto module = load_module(context, "elgamal");
    expect_round_trip(*module, bytes_from_hex(ELGAMAL_TEST_KEY_PAIR_HEX), random_bytes(20000, DATA_SEED + 9));
}

void elgamal_rejects_damage_and_public_key(const TestContext& context) {
    const auto module = load_module(context, "elgamal");
    const Bytes key = bytes_from_hex(ELGAMAL_TEST_KEY_PAIR_HEX);
    const Bytes public_key(key.begin(), key.begin() + 256);
    const CryptResult encrypted = run_crypt(*module, CRYPTO_OPERATION_ENCRYPT, public_key, bytes_from_text("secret"));
    expect(encrypted.status == CRYPTO_STATUS_OK, "шифрование открытым ключом должно работать");
    expect(run_crypt(*module, CRYPTO_OPERATION_DECRYPT, public_key, encrypted.output).status == CRYPTO_STATUS_INVALID_KEY,
           "открытый ключ не должен расшифровывать");

    Bytes damaged = encrypted.output;
    damaged[300] ^= 0x01;
    expect(run_crypt(*module, CRYPTO_OPERATION_DECRYPT, key, damaged).status == CRYPTO_STATUS_INVALID_INPUT,
           "повреждённый шифротекст должен отклоняться");
    damaged.pop_back();
    expect(run_crypt(*module, CRYPTO_OPERATION_DECRYPT, key, damaged).status == CRYPTO_STATUS_INVALID_INPUT,
           "обрезанный шифротекст должен отклоняться");
}

const TestCase TEST_CASES[] = {
    {"table: контрольный пример ABCDEFGHIJ", table_known_answer},
    {"table: случайные данные, 17 и 255 столбцов", table_random_data},
    {"table: пустые и короткие данные", table_short_and_empty_data},
    {"table: неверные ключи", table_rejects_invalid_keys},
    {"vernam: контрольный пример 41 xor 0F", vernam_known_answer},
    {"vernam: случайные данные", vernam_random_data},
    {"vernam: пустые данные и несовпадение длины", vernam_empty_data_and_length_mismatch},
    {"elgamal: детерминированное шифрование с nonce", elgamal_deterministic_encryption},
    {"elgamal: границы блоков и PKCS#7", elgamal_block_boundaries},
    {"elgamal: случайные данные", elgamal_random_data},
    {"elgamal: повреждения и открытый ключ", elgamal_rejects_damage_and_public_key},
};

}

int main(int argc, char** argv) {
    cryptotool::configure_console();
    const std::vector<std::string> arguments = cryptotool::utf8_arguments(argc, argv);
    const plugin_tests::TestContext context{cryptotool::executable_directory(arguments.front())};

    int failed = 0;
    for (const plugin_tests::TestCase& test : plugin_tests::TEST_CASES) {
        try {
            test.run(context);
            std::cout << "[ OK ] " << test.name << '\n';
        } catch (const plugin_tests::TestFailure& failure) {
            ++failed;
            std::cout << "[FAIL] " << test.name << ": " << failure.message << '\n';
        } catch (const std::exception& error) {
            ++failed;
            std::cout << "[FAIL] " << test.name << ": " << error.what() << '\n';
        }
    }
    const auto total = static_cast<int>(std::size(plugin_tests::TEST_CASES));
    std::cout << "\nПройдено " << total - failed << " из " << total << " тестов.\n";
    return failed == 0 ? 0 : 1;
}
