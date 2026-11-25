#pragma once

#include "secure_memory.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>

namespace cryptotool {

struct InputStream {
    std::unique_ptr<std::ifstream> file;
    std::istream* stream = nullptr;
};

// Output goes to a temporary file next to the target and replaces it only after a successful commit,
// so a failed operation never leaves a truncated result or destroys an existing file.
struct PendingFile {
    std::filesystem::path target;
    std::filesystem::path temporary;
    std::ofstream stream;
    bool committed = false;

    PendingFile() = default;
    PendingFile(const PendingFile&) = delete;
    PendingFile& operator=(const PendingFile&) = delete;
    ~PendingFile();
};

struct OutputStream {
    std::unique_ptr<PendingFile> file;
    std::ostream* stream = nullptr;
};

enum class FileAccess { SHARED, OWNER_ONLY };

InputStream open_input_stream(const std::optional<std::string>& path, const std::string& purpose);
OutputStream open_output_stream(const std::optional<std::string>& path, FileAccess access);
void commit_output(OutputStream& output);

SecureBytes read_key_bytes(std::istream& input, std::size_t size_limit);

void require_distinct_files(const std::optional<std::string>& first, const std::optional<std::string>& second,
                            const std::string& message);

}
