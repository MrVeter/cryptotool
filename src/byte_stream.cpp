#include "byte_stream.h"

#include <istream>
#include <ostream>
#include <stdexcept>

namespace cryptotool {

std::size_t read_bytes(std::istream& input, std::uint8_t* destination, std::size_t size) {
    input.read(reinterpret_cast<char*>(destination), static_cast<std::streamsize>(size));
    if (input.bad()) throw std::runtime_error("Ошибка чтения входных данных.");
    return static_cast<std::size_t>(input.gcount());
}

void write_bytes(std::ostream& output, const std::uint8_t* source, std::size_t size) {
    output.write(reinterpret_cast<const char*>(source), static_cast<std::streamsize>(size));
    if (!output) throw std::runtime_error("Ошибка записи результата.");
}

bool has_more_bytes(std::istream& input) {
    return input.peek() != std::istream::traits_type::eof();
}

}
