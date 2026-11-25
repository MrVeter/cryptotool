#pragma once

#include <string>
#include <vector>

namespace cryptotool {

constexpr int EXIT_CODE_SUCCESS = 0;
constexpr int EXIT_CODE_FAILURE = 1;
constexpr int EXIT_CODE_USAGE_ERROR = 2;

int run_application(const std::vector<std::string>& arguments);

}
