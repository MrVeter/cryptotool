#ifndef CRYPTO_PLUGIN_API_H
#define CRYPTO_PLUGIN_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define CRYPTO_PLUGIN_EXPORT __declspec(dllexport)
#else
#define CRYPTO_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ConstBuffer {
    const uint8_t* data;
    size_t size;
} ConstBuffer;

typedef struct MutBuffer {
    uint8_t* data;
    size_t size;
} MutBuffer;

/*
 * key_size is the default length of a generated key in bytes.
 * When key_follows_data_length is non-zero the key is a keystream:
 * byte i of the key is applied to byte i of the data, so the host
 * passes the key slice that matches every processed chunk.
 */
typedef struct AlgorithmInfo {
    const char* algorithm_name;
    size_t key_size;
    int key_follows_data_length;
} AlgorithmInfo;

enum CryptoOperation {
    CRYPTO_OPERATION_ENCRYPT = 1,
    CRYPTO_OPERATION_DECRYPT = 2
};

enum CryptoStatus {
    CRYPTO_STATUS_OK = 0,
    CRYPTO_STATUS_INVALID_KEY = 1,
    CRYPTO_STATUS_INVALID_INPUT = 2,
    CRYPTO_STATUS_OUTPUT_TOO_SMALL = 3,
    CRYPTO_STATUS_RANDOM_FAILURE = 4,
    CRYPTO_STATUS_INTERNAL_ERROR = 5,
    CRYPTO_STATUS_INVALID_ARGUMENT = 6
};

/*
 * Every function returns CRYPTO_STATUS_OK or another CryptoStatus value and never throws.
 * The host allocates output buffers: output->size holds the capacity on entry
 * and the number of written bytes on success.
 */
typedef const AlgorithmInfo* (*GetAlgorithmInfoFunction)(void);
typedef size_t (*GetOutputSizeFunction)(size_t input_size, int operation_type);
typedef int (*GenerateKeyFunction)(MutBuffer* key);
typedef int (*CryptFunction)(ConstBuffer key, ConstBuffer input, MutBuffer* output);
typedef int (*CryptWithNonceFunction)(ConstBuffer key, ConstBuffer input, ConstBuffer nonce, MutBuffer* output);

#ifdef __cplusplus
}
#endif

#endif
