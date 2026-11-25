#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>

namespace cryptotool {

std::size_t read_bytes(std::istream& input, std::uint8_t* destination, std::size_t size);
void write_bytes(std::ostream& output, const std::uint8_t* source, std::size_t size);
bool has_more_bytes(std::istream& input);

}
