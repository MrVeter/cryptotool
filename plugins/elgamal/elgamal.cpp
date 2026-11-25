#include "crypto_plugin_api.h"
#include "plugin_support.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <memory>

namespace elgamal {

using plugin_support::fail;
using plugin_support::require;

constexpr size_t ELEMENT_SIZE = 256;
constexpr size_t PUBLIC_KEY_SIZE = ELEMENT_SIZE;
constexpr size_t KEY_PAIR_SIZE = 2 * ELEMENT_SIZE;
constexpr size_t PLAIN_BLOCK_SIZE = 254;
constexpr size_t ENCODED_BLOCK_SIZE = PLAIN_BLOCK_SIZE + 1;
constexpr size_t CIPHER_BLOCK_SIZE = 2 * ELEMENT_SIZE;
constexpr uint8_t ENCODING_MARKER = 0x01;
// RFC 3526, section 8: a 320-bit exponent matches the strength of the 2048-bit group.
constexpr int EXPONENT_BITS = 320;

const AlgorithmInfo ALGORITHM_INFO{"elgamal", KEY_PAIR_SIZE, 0};

using BigNumber = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using BigNumberContext = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

void require_openssl(bool succeeded) {
    require(succeeded, CRYPTO_STATUS_INTERNAL_ERROR);
}

BigNumber make_number() {
    BigNumber number(BN_new(), BN_clear_free);
    require_openssl(number != nullptr);
    return number;
}

BigNumber number_from_bytes(const uint8_t* bytes, size_t size) {
    BigNumber number = make_number();
    require_openssl(BN_bin2bn(bytes, static_cast<int>(size), number.get()) != nullptr);
    return number;
}

void number_to_bytes(const BIGNUM* number, uint8_t* bytes, size_t size) {
    require_openssl(BN_bn2binpad(number, bytes, static_cast<int>(size)) == static_cast<int>(size));
}

// RFC 3526 group 14: safe prime p = 2q + 1, generator 2 of the subgroup of quadratic residues of order q.
struct Group {
    BigNumber prime{BN_get_rfc3526_prime_2048(nullptr), BN_clear_free};
    BigNumber generator = make_number();
    BigNumber subgroup_order = make_number();
    BigNumberContext context{BN_CTX_new(), BN_CTX_free};

    Group() {
        require_openssl(prime != nullptr && context != nullptr);
        require_openssl(BN_set_word(generator.get(), 2) == 1);
        require_openssl(BN_rshift1(subgroup_order.get(), prime.get()) == 1);
    }
};

void modular_power(BIGNUM* result, const BIGNUM* base, const BIGNUM* exponent, Group& group) {
    require_openssl(BN_mod_exp_mont_consttime(result, base, exponent, group.prime.get(),
                                              group.context.get(), nullptr) == 1);
}

void require_subgroup_element(const BIGNUM* element, Group& group, int status) {
    BigNumber upper_bound = make_number();
    BigNumber check = make_number();
    require_openssl(BN_copy(upper_bound.get(), group.prime.get()) != nullptr);
    require_openssl(BN_sub_word(upper_bound.get(), 1) == 1);
    require(BN_cmp(element, BN_value_one()) > 0 && BN_cmp(element, upper_bound.get()) < 0, status);
    require_openssl(BN_mod_exp(check.get(), element, group.subgroup_order.get(), group.prime.get(),
                               group.context.get()) == 1);
    require(BN_is_one(check.get()) == 1, status);
}

void random_exponent(BIGNUM* exponent) {
    require(BN_priv_rand(exponent, EXPONENT_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1,
            CRYPTO_STATUS_RANDOM_FAILURE);
    require_openssl(BN_add_word(exponent, 2) == 1);
    BN_set_flags(exponent, BN_FLG_CONSTTIME);
}

void exponent_from_nonce(BIGNUM* exponent, const BIGNUM* nonce, size_t block_index) {
    require_openssl(BN_copy(exponent, nonce) != nullptr);
    require_openssl(BN_add_word(exponent, static_cast<BN_ULONG>(block_index)) == 1);
    BN_mask_bits(exponent, EXPONENT_BITS);
    require_openssl(BN_add_word(exponent, 2) == 1);
}

BigNumber read_public_key(ConstBuffer key, Group& group) {
    require(key.data != nullptr && (key.size == PUBLIC_KEY_SIZE || key.size == KEY_PAIR_SIZE),
            CRYPTO_STATUS_INVALID_KEY);
    BigNumber public_key = number_from_bytes(key.data, PUBLIC_KEY_SIZE);
    require_subgroup_element(public_key.get(), group, CRYPTO_STATUS_INVALID_KEY);
    return public_key;
}

BigNumber read_private_key(ConstBuffer key, Group& group) {
    require(key.data != nullptr && key.size == KEY_PAIR_SIZE, CRYPTO_STATUS_INVALID_KEY);
    BigNumber public_key = read_public_key(key, group);
    BigNumber private_key = number_from_bytes(key.data + PUBLIC_KEY_SIZE, ELEMENT_SIZE);
    BN_set_flags(private_key.get(), BN_FLG_CONSTTIME);
    require(BN_cmp(private_key.get(), BN_value_one()) > 0 &&
                BN_cmp(private_key.get(), group.subgroup_order.get()) < 0,
            CRYPTO_STATUS_INVALID_KEY);
    BigNumber derived_public_key = make_number();
    modular_power(derived_public_key.get(), group.generator.get(), private_key.get(), group);
    require(BN_cmp(derived_public_key.get(), public_key.get()) == 0, CRYPTO_STATUS_INVALID_KEY);
    return private_key;
}

size_t padded_size(size_t input_size) {
    return (input_size / PLAIN_BLOCK_SIZE + 1) * PLAIN_BLOCK_SIZE;
}

size_t output_size(size_t input_size, int operation_type) {
    if (operation_type == CRYPTO_OPERATION_ENCRYPT) {
        return padded_size(input_size) / PLAIN_BLOCK_SIZE * CIPHER_BLOCK_SIZE;
    }
    if (operation_type == CRYPTO_OPERATION_DECRYPT) {
        return input_size / CIPHER_BLOCK_SIZE * PLAIN_BLOCK_SIZE;
    }
    return 0;
}

// PKCS#7 padding applied to the whole input, block i holds bytes [i*254, i*254+254).
void fill_padded_block(ConstBuffer input, size_t block_index, std::array<uint8_t, ENCODED_BLOCK_SIZE>& encoded) {
    const size_t pad_value = padded_size(input.size) - input.size;
    const size_t block_start = block_index * PLAIN_BLOCK_SIZE;
    const size_t copied = block_start < input.size ? std::min(PLAIN_BLOCK_SIZE, input.size - block_start) : 0;
    encoded[0] = ENCODING_MARKER;
    std::copy_n(input.data + block_start, copied, encoded.begin() + 1);
    std::fill(encoded.begin() + 1 + static_cast<std::ptrdiff_t>(copied), encoded.end(),
              static_cast<uint8_t>(pad_value));
}

// p = 2q + 1 with p = 3 (mod 4), so -1 is a non-residue and exactly one of r and p - r is a quadratic residue.
// The block r = 0x01 || data (r < p / 2) is mapped to that residue, which lies in the generator's subgroup.
void encode_into_subgroup(BIGNUM* message, const BIGNUM* encoded_number, Group& group) {
    const int legendre_symbol = BN_kronecker(encoded_number, group.prime.get(), group.context.get());
    require_openssl(legendre_symbol == 1 || legendre_symbol == -1);
    if (legendre_symbol == 1) {
        require_openssl(BN_copy(message, encoded_number) != nullptr);
    } else {
        require_openssl(BN_sub(message, group.prime.get(), encoded_number) == 1);
    }
}

void decode_from_subgroup(BIGNUM* encoded_number, const BIGNUM* message, Group& group) {
    require(BN_kronecker(message, group.prime.get(), group.context.get()) == 1, CRYPTO_STATUS_INVALID_INPUT);
    BigNumber negated = make_number();
    require_openssl(BN_sub(negated.get(), group.prime.get(), message) == 1);
    const BIGNUM* smaller = BN_cmp(message, negated.get()) < 0 ? message : negated.get();
    require_openssl(BN_copy(encoded_number, smaller) != nullptr);
}

void encrypt_blocks(ConstBuffer key, ConstBuffer input, const ConstBuffer* nonce, MutBuffer* output) {
    Group group;
    BigNumber public_key = read_public_key(key, group);
    plugin_support::require_input(input);
    const size_t required_size = output_size(input.size, CRYPTO_OPERATION_ENCRYPT);
    plugin_support::require_output(output, required_size);
    BigNumber nonce_number = make_number();
    if (nonce != nullptr) {
        require(nonce->data != nullptr && nonce->size > 0 && nonce->size <= ELEMENT_SIZE,
                CRYPTO_STATUS_INVALID_ARGUMENT);
        nonce_number = number_from_bytes(nonce->data, nonce->size);
    }

    BigNumber encoded_number = make_number();
    BigNumber message = make_number();
    BigNumber ephemeral = make_number();
    BigNumber shared_secret = make_number();
    BigNumber first_part = make_number();
    BigNumber second_part = make_number();
    std::array<uint8_t, ENCODED_BLOCK_SIZE> encoded{};

    const size_t block_count = required_size / CIPHER_BLOCK_SIZE;
    for (size_t block_index = 0; block_index < block_count; ++block_index) {
        fill_padded_block(input, block_index, encoded);
        require_openssl(BN_bin2bn(encoded.data(), static_cast<int>(encoded.size()), encoded_number.get()) != nullptr);
        OPENSSL_cleanse(encoded.data(), encoded.size());
        encode_into_subgroup(message.get(), encoded_number.get(), group);

        if (nonce != nullptr) {
            exponent_from_nonce(ephemeral.get(), nonce_number.get(), block_index);
        } else {
            random_exponent(ephemeral.get());
        }
        modular_power(first_part.get(), group.generator.get(), ephemeral.get(), group);
        modular_power(shared_secret.get(), public_key.get(), ephemeral.get(), group);
        require_openssl(BN_mod_mul(second_part.get(), message.get(), shared_secret.get(), group.prime.get(),
                                   group.context.get()) == 1);

        uint8_t* block_output = output->data + block_index * CIPHER_BLOCK_SIZE;
        number_to_bytes(first_part.get(), block_output, ELEMENT_SIZE);
        number_to_bytes(second_part.get(), block_output + ELEMENT_SIZE, ELEMENT_SIZE);
    }
    output->size = required_size;
}

void decode_block(const uint8_t* cipher_block, const BIGNUM* private_key, Group& group, uint8_t* plain_block) {
    BigNumber first_part = number_from_bytes(cipher_block, ELEMENT_SIZE);
    BigNumber second_part = number_from_bytes(cipher_block + ELEMENT_SIZE, ELEMENT_SIZE);
    require(BN_cmp(first_part.get(), BN_value_one()) > 0 && BN_cmp(first_part.get(), group.prime.get()) < 0,
            CRYPTO_STATUS_INVALID_INPUT);
    require(BN_is_zero(second_part.get()) == 0 && BN_cmp(second_part.get(), group.prime.get()) < 0,
            CRYPTO_STATUS_INVALID_INPUT);

    BigNumber shared_secret = make_number();
    BigNumber inverse = make_number();
    BigNumber message = make_number();
    BigNumber encoded_number = make_number();
    modular_power(shared_secret.get(), first_part.get(), private_key, group);
    require_openssl(BN_mod_inverse(inverse.get(), shared_secret.get(), group.prime.get(), group.context.get()) != nullptr);
    require_openssl(BN_mod_mul(message.get(), second_part.get(), inverse.get(), group.prime.get(),
                               group.context.get()) == 1);

    decode_from_subgroup(encoded_number.get(), message.get(), group);

    std::array<uint8_t, ENCODED_BLOCK_SIZE> encoded{};
    require(BN_num_bytes(encoded_number.get()) <= static_cast<int>(ENCODED_BLOCK_SIZE), CRYPTO_STATUS_INVALID_INPUT);
    number_to_bytes(encoded_number.get(), encoded.data(), encoded.size());
    const bool marker_matches = encoded[0] == ENCODING_MARKER;
    std::copy(encoded.begin() + 1, encoded.end(), plain_block);
    OPENSSL_cleanse(encoded.data(), encoded.size());
    require(marker_matches, CRYPTO_STATUS_INVALID_INPUT);
}

size_t remove_padding(const uint8_t* plain_data, size_t padded_length) {
    require(padded_length >= PLAIN_BLOCK_SIZE, CRYPTO_STATUS_INVALID_INPUT);
    const uint8_t pad_value = plain_data[padded_length - 1];
    require(pad_value >= 1 && pad_value <= PLAIN_BLOCK_SIZE, CRYPTO_STATUS_INVALID_INPUT);
    const uint8_t* padding_begin = plain_data + padded_length - pad_value;
    require(std::all_of(padding_begin, plain_data + padded_length,
                        [pad_value](uint8_t byte) { return byte == pad_value; }),
            CRYPTO_STATUS_INVALID_INPUT);
    return padded_length - pad_value;
}

void decrypt_blocks(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    Group group;
    BigNumber private_key = read_private_key(key, group);
    plugin_support::require_input(input);
    require(input.size > 0 && input.size % CIPHER_BLOCK_SIZE == 0, CRYPTO_STATUS_INVALID_INPUT);
    const size_t padded_length = output_size(input.size, CRYPTO_OPERATION_DECRYPT);
    plugin_support::require_output(output, padded_length);
    const size_t block_count = input.size / CIPHER_BLOCK_SIZE;
    try {
        for (size_t block_index = 0; block_index < block_count; ++block_index) {
            decode_block(input.data + block_index * CIPHER_BLOCK_SIZE, private_key.get(), group,
                         output->data + block_index * PLAIN_BLOCK_SIZE);
        }
        output->size = remove_padding(output->data, padded_length);
    } catch (...) {
        OPENSSL_cleanse(output->data, padded_length);
        throw;
    }
    OPENSSL_cleanse(output->data + output->size, padded_length - output->size);
}

void generate_key_pair(MutBuffer* key) {
    require(key != nullptr && key->data != nullptr, CRYPTO_STATUS_INVALID_ARGUMENT);
    require(key->size == KEY_PAIR_SIZE, CRYPTO_STATUS_INVALID_KEY);
    Group group;
    BigNumber private_key = make_number();
    BigNumber public_key = make_number();
    random_exponent(private_key.get());
    modular_power(public_key.get(), group.generator.get(), private_key.get(), group);
    number_to_bytes(public_key.get(), key->data, ELEMENT_SIZE);
    number_to_bytes(private_key.get(), key->data + PUBLIC_KEY_SIZE, ELEMENT_SIZE);
}

}

extern "C" {

CRYPTO_PLUGIN_EXPORT const AlgorithmInfo* get_algorithm_info(void) {
    return &elgamal::ALGORITHM_INFO;
}

CRYPTO_PLUGIN_EXPORT size_t get_output_size(size_t input_size, int operation_type) {
    return elgamal::output_size(input_size, operation_type);
}

CRYPTO_PLUGIN_EXPORT int generate_key(MutBuffer* key) {
    return plugin_support::run_guarded([&] { elgamal::generate_key_pair(key); });
}

CRYPTO_PLUGIN_EXPORT int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return plugin_support::run_guarded([&] { elgamal::encrypt_blocks(key, input, nullptr, output); });
}

CRYPTO_PLUGIN_EXPORT int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return plugin_support::run_guarded([&] { elgamal::decrypt_blocks(key, input, output); });
}

// Test-only entry point: the per-block exponent k is derived from the nonce so the ciphertext is reproducible.
CRYPTO_PLUGIN_EXPORT int encrypt_with_nonce(ConstBuffer key, ConstBuffer input, ConstBuffer nonce, MutBuffer* output) {
    return plugin_support::run_guarded([&] { elgamal::encrypt_blocks(key, input, &nonce, output); });
}

}
