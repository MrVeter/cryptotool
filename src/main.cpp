#include "application.h"
#include "platform.h"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        cryptotool::configure_console();
        std::ios::sync_with_stdio(false);
        return cryptotool::run_application(cryptotool::utf8_arguments(argc, argv));
    } catch (const std::exception& error) {
        std::cerr << "Ошибка: " << error.what() << '\n';
    } catch (...) {
        std::cerr << "Ошибка: непредвиденный сбой.\n";
    }
    return cryptotool::EXIT_CODE_FAILURE;
}
