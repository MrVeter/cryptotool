#include "stream_io.h"

#include "byte_stream.h"
#include "command_line.h"
#include "platform.h"

#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>

namespace cryptotool {

namespace fs = std::filesystem;

namespace {

bool is_named_file(const std::optional<std::string>& path) {
    return path.has_value() && *path != STANDARD_STREAM_ARGUMENT;
}

fs::file_status checked_status(const fs::path& path, const std::string& shown_path) {
    std::error_code error;
    const fs::file_status status = fs::status(path, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        throw std::runtime_error("Нет доступа к " + shown_path + ": недостаточно прав.");
    }
    return status;
}

fs::path temporary_path_for(const fs::path& target) {
    std::random_device random_source;
    std::ostringstream suffix;
    suffix << ".tmp-" << std::hex << random_source() << random_source();
    fs::path temporary = target;
    temporary += suffix.str();
    return temporary;
}

}

PendingFile::~PendingFile() {
    if (committed || temporary.empty()) return;
    if (stream.is_open()) stream.close();
    std::error_code ignored;
    fs::remove(temporary, ignored);
}

InputStream open_input_stream(const std::optional<std::string>& path, const std::string& purpose) {
    InputStream input;
    if (!is_named_file(path)) {
        input.stream = &std::cin;
        return input;
    }
    const fs::path file_path = path_from_utf8(*path);
    const fs::file_status status = checked_status(file_path, *path);
    if (!fs::exists(status)) throw std::runtime_error("Не найден " + purpose + ": " + *path);
    if (fs::is_directory(status)) throw std::runtime_error("Вместо файла указан каталог: " + *path);

    input.file = std::make_unique<std::ifstream>(file_path, std::ios::binary);
    if (!*input.file) throw std::runtime_error("Нет доступа на чтение (" + purpose + "): " + *path);
    input.stream = input.file.get();
    return input;
}

OutputStream open_output_stream(const std::optional<std::string>& path, FileAccess access) {
    OutputStream output;
    if (!is_named_file(path)) {
        output.stream = &std::cout;
        return output;
    }
    auto pending = std::make_unique<PendingFile>();
    pending->target = fs::absolute(path_from_utf8(*path));
    const fs::path directory = pending->target.parent_path();
    if (!fs::is_directory(checked_status(directory, path_to_utf8(directory)))) {
        throw std::runtime_error("Каталог не существует: " + path_to_utf8(directory));
    }
    if (fs::is_directory(checked_status(pending->target, *path))) {
        throw std::runtime_error("Вместо файла указан каталог: " + *path);
    }

    pending->temporary = temporary_path_for(pending->target);
    pending->stream.open(pending->temporary, std::ios::binary | std::ios::trunc);
    if (!pending->stream) throw std::runtime_error("Нет доступа на запись в каталог: " + path_to_utf8(directory));
    if (access == FileAccess::OWNER_ONLY) restrict_to_owner(pending->temporary);

    output.stream = &pending->stream;
    output.file = std::move(pending);
    return output;
}

void commit_output(OutputStream& output) {
    output.stream->flush();
    if (!*output.stream) throw std::runtime_error("Ошибка записи результата. Проверьте свободное место на диске.");
    if (!output.file) return;
    PendingFile& pending = *output.file;
    pending.stream.close();
    if (!pending.stream) throw std::runtime_error("Не удалось завершить запись файла " + path_to_utf8(pending.target) + ".");
    replace_file(pending.temporary, pending.target);
    pending.committed = true;
}

SecureBytes read_key_bytes(std::istream& input, std::size_t size_limit) {
    SecureBytes key(size_limit + 1);
    const std::size_t key_size = read_bytes(input, key.data(), key.size());
    if (key_size > size_limit) throw std::runtime_error("Файл ключа слишком большой.");
    if (key_size == 0) throw std::runtime_error("Ключ пуст.");
    key.resize(key_size);
    return key;
}

void require_distinct_files(const std::optional<std::string>& first, const std::optional<std::string>& second,
                            const std::string& message) {
    if (!is_named_file(first) || !is_named_file(second)) return;
    const fs::path first_path = path_from_utf8(*first);
    const fs::path second_path = path_from_utf8(*second);
    std::error_code error;
    const bool both_exist = fs::exists(first_path, error) && fs::exists(second_path, error);
    const bool same_existing_file = both_exist && fs::equivalent(first_path, second_path, error);
    const bool same_name = fs::absolute(first_path).lexically_normal() == fs::absolute(second_path).lexically_normal();
    if (same_existing_file || same_name) throw std::runtime_error(message);
}

}
