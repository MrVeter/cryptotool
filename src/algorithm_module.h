#pragma once

#include "crypto_plugin_api.h"

namespace cryptotool {

// The business logic depends only on this table of functions, not on how the library was loaded.
struct AlgorithmModule {
    const AlgorithmInfo* info = nullptr;
    GetOutputSizeFunction get_output_size = nullptr;
    GenerateKeyFunction generate_key = nullptr;
    CryptFunction encrypt = nullptr;
    CryptFunction decrypt = nullptr;
};

}
