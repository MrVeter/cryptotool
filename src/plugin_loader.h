#pragma once

#include "algorithm_module.h"

#include <array>
#include <filesystem>
#include <memory>
#include <string>

namespace cryptotool {

struct AlgorithmEntry {
    const char* name;
    const char* library_base_name;
    const char* description;
};

constexpr std::array<AlgorithmEntry, 3> SUPPORTED_ALGORITHMS{{
    {"elgamal", "elgamal", "асимметричный шифр Эль-Гамаля, 2048 бит (RFC 3526), ключ 512 байт"},
    {"table", "table", "табличная перестановка, ключ из N байт-меток 1..N (2 <= N <= 255)"},
    {"vernam", "vernam", "шифр Вернама (одноразовый блокнот), ключ равен длине данных"},
}};

struct LoadedAlgorithm {
    void* library = nullptr;
    AlgorithmModule module;

    LoadedAlgorithm() = default;
    LoadedAlgorithm(const LoadedAlgorithm&) = delete;
    LoadedAlgorithm& operator=(const LoadedAlgorithm&) = delete;
    ~LoadedAlgorithm();
};

const AlgorithmEntry* find_algorithm(const std::string& name);
std::string library_file_name(const AlgorithmEntry& entry);
std::unique_ptr<LoadedAlgorithm> load_algorithm(const AlgorithmEntry& entry, const std::filesystem::path& directory);

}
