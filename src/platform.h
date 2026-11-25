#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace cryptotool {

void configure_console();
void set_standard_streams_binary();
std::vector<std::string> utf8_arguments(int argc, char** argv);
std::filesystem::path executable_directory(const std::string& program_argument);
std::filesystem::path path_from_utf8(const std::string& text);
std::string path_to_utf8(const std::filesystem::path& path);
void secure_wipe(void* data, std::size_t size);
void restrict_to_owner(const std::filesystem::path& path);
void replace_file(const std::filesystem::path& source, const std::filesystem::path& target);

void* open_shared_library(const std::filesystem::path& path, std::string& error_message);
void* find_library_symbol(void* library, const char* name);
void close_shared_library(void* library);

}
