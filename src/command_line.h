#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace cryptotool {

constexpr const char* STANDARD_STREAM_ARGUMENT = "-";

enum class Mode { NOT_SET, ENCRYPT, DECRYPT, GENERATE_KEY };

struct Options {
    bool show_help = false;
    std::string algorithm;
    Mode mode = Mode::NOT_SET;
    std::optional<std::string> key_path;
    std::optional<std::string> input_path;
    std::optional<std::string> output_path;
    std::optional<std::string> save_key_path;
    std::optional<std::size_t> key_length;
    bool generate_key = false;
    bool write_key = false;
};

struct UsageError {
    std::string message;
};

Options parse_arguments(const std::vector<std::string>& arguments);
void validate_options(const Options& options);
bool reads_standard_input(const std::optional<std::string>& path);
bool writes_standard_output(const std::optional<std::string>& path);
bool creates_key(const Options& options);
std::string help_text(const std::string& program_name);

}
