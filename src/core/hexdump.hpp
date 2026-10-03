#pragma once

#include <cstddef>
#include <string>

#include "core/byte_io.hpp"

namespace opends2 {

// Classic 16-bytes-per-line hex + ASCII dump. Output is truncated after max_bytes.
std::string hexdump(ByteView data, std::size_t max_bytes = 4096);

}  // namespace opends2
