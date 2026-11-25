#include "plugin_loader.h"

#include "platform.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace cryptotool {

namespace fs = std::filesystem;

namespace {

template <typename Function>
Function resolve_function(void* library, const char* symbol_name, const std::string& library_name) {
    void* symbol = find_library_symbol(library, symbol_name);
    if (symbol == nullptr) {
        throw std::runtime_error("В библиотеке " + library_name + " нет функции " + symbol_name + ".");
    }
    Function function = nullptr;
    static_assert(sizeof(function) == sizeof(symbol), "function and data pointers must have equal size");
    std::memcpy(&function, &symbol, sizeof(function));
    return function;
}

}

LoadedAlgorithm::~LoadedAlgorithm() {
    close_shared_library(library);
}

const AlgorithmEntry* find_algorithm(const std::string& name) {
    const auto found = std::find_if(SUPPORTED_ALGORITHMS.begin(), SUPPORTED_ALGORITHMS.end(),
                                    [&name](const AlgorithmEntry& entry) { return name == entry.name; });
    return found == SUPPORTED_ALGORITHMS.end() ? nullptr : &*found;
}

std::string library_file_name(const AlgorithmEntry& entry) {
#if defined(_WIN32)
    return std::string(entry.library_base_name) + ".dll";
#elif defined(__APPLE__)
    return "lib" + std::string(entry.library_base_name) + ".dylib";
#else
    return "lib" + std::string(entry.library_base_name) + ".so";
#endif
}

std::unique_ptr<LoadedAlgorithm> load_algorithm(const AlgorithmEntry& entry, const fs::path& directory) {
    const std::string file_name = library_file_name(entry);
    const fs::path library_path = directory / file_name;
    std::error_code status_error;
    if (!fs::exists(library_path, status_error)) {
        throw std::runtime_error("Не найдена библиотека алгоритма «" + std::string(entry.name) + "»: " +
                                 path_to_utf8(library_path));
    }

    auto loaded = std::make_unique<LoadedAlgorithm>();
    std::string load_error;
    loaded->library = open_shared_library(library_path, load_error);
    if (loaded->library == nullptr) {
        throw std::runtime_error("Не удалось загрузить библиотеку " + path_to_utf8(library_path) + ": " + load_error);
    }

    AlgorithmModule& module = loaded->module;
    const auto get_info = resolve_function<GetAlgorithmInfoFunction>(loaded->library, "get_algorithm_info", file_name);
    module.get_output_size = resolve_function<GetOutputSizeFunction>(loaded->library, "get_output_size", file_name);
    module.generate_key = resolve_function<GenerateKeyFunction>(loaded->library, "generate_key", file_name);
    module.encrypt = resolve_function<CryptFunction>(loaded->library, "encrypt", file_name);
    module.decrypt = resolve_function<CryptFunction>(loaded->library, "decrypt", file_name);

    module.info = get_info();
    if (module.info == nullptr || module.info->algorithm_name == nullptr ||
        std::strcmp(module.info->algorithm_name, entry.name) != 0) {
        throw std::runtime_error("Библиотека " + file_name + " не реализует алгоритм «" + entry.name + "».");
    }
    return loaded;
}

}
