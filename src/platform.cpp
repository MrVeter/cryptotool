#include "platform.h"

#include <stdexcept>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#else
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#endif

#include <cstring>

namespace cryptotool {

namespace fs = std::filesystem;

#ifdef _WIN32

namespace {

std::string wide_to_utf8(const wchar_t* text) {
    const int length = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 0) throw std::runtime_error("Не удалось преобразовать аргумент командной строки в UTF-8.");
    std::string result(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), length, nullptr, nullptr);
    result.pop_back();
    return result;
}

}

void configure_console() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

void set_standard_streams_binary() {
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
}

std::vector<std::string> utf8_arguments(int, char**) {
    int count = 0;
    LPWSTR* wide_arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    if (wide_arguments == nullptr) throw std::runtime_error("Не удалось прочитать аргументы командной строки.");
    std::vector<std::string> arguments;
    try {
        for (int index = 0; index < count; ++index) arguments.push_back(wide_to_utf8(wide_arguments[index]));
    } catch (...) {
        LocalFree(wide_arguments);
        throw;
    }
    LocalFree(wide_arguments);
    return arguments;
}

fs::path executable_directory(const std::string&) {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length == buffer.size()) throw std::runtime_error("Не удалось определить каталог программы.");
    buffer.resize(length);
    return fs::path(buffer).parent_path();
}

void secure_wipe(void* data, std::size_t size) {
    if (data != nullptr && size > 0) SecureZeroMemory(data, size);
}

void restrict_to_owner(const fs::path&) {}

void replace_file(const fs::path& source, const fs::path& target) {
    if (!MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("Не удалось сохранить файл " + path_to_utf8(target) + ".");
    }
}

void* open_shared_library(const fs::path& path, std::string& error_message) {
    HMODULE library = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (library == nullptr) error_message = "код ошибки Windows " + std::to_string(GetLastError());
    return reinterpret_cast<void*>(library);
}

void* find_library_symbol(void* library, const char* name) {
    FARPROC address = GetProcAddress(reinterpret_cast<HMODULE>(library), name);
    void* symbol = nullptr;
    static_assert(sizeof(symbol) == sizeof(address), "function and data pointers must have equal size");
    std::memcpy(&symbol, &address, sizeof(symbol));
    return symbol;
}

void close_shared_library(void* library) {
    if (library != nullptr) FreeLibrary(reinterpret_cast<HMODULE>(library));
}

#else

void configure_console() {}

void set_standard_streams_binary() {}

std::vector<std::string> utf8_arguments(int argc, char** argv) {
    return std::vector<std::string>(argv, argv + argc);
}

fs::path executable_directory(const std::string& program_argument) {
    std::error_code error;
    const fs::path self_link = fs::read_symlink("/proc/self/exe", error);
    if (!error) return self_link.parent_path();
    return fs::canonical(fs::path(program_argument)).parent_path();
}

void secure_wipe(void* data, std::size_t size) {
    if (data == nullptr || size == 0) return;
#if defined(__GLIBC__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    explicit_bzero(data, size);
#else
    volatile unsigned char* bytes = static_cast<volatile unsigned char*>(data);
    while (size-- > 0) *bytes++ = 0;
#endif
}

void restrict_to_owner(const fs::path& path) {
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
}

void replace_file(const fs::path& source, const fs::path& target) {
    fs::rename(source, target);
}

void* open_shared_library(const fs::path& path, std::string& error_message) {
    void* library = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) {
        const char* reason = dlerror();
        error_message = reason != nullptr ? reason : "неизвестная ошибка dlopen";
    }
    return library;
}

void* find_library_symbol(void* library, const char* name) {
    return dlsym(library, name);
}

void close_shared_library(void* library) {
    if (library != nullptr) dlclose(library);
}

#endif

fs::path path_from_utf8(const std::string& text) {
    return fs::u8path(text);
}

std::string path_to_utf8(const fs::path& path) {
    return path.u8string();
}

}
