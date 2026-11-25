#include "command_line.h"

#include "plugin_loader.h"

#include <algorithm>
#include <array>
#include <limits>
#include <sstream>

namespace cryptotool {

namespace {

enum class OptionId { HELP, ALGORITHM, MODE, KEY, INPUT, OUTPUT, GENERATE_KEY, SAVE_KEY, WRITE_KEY, KEY_LENGTH };

struct OptionSpec {
    OptionId id;
    char short_name;
    const char* long_name;
    bool takes_value;
    const char* value_name;
    const char* description;
};

constexpr std::array<OptionSpec, 10> OPTION_SPECS{{
    {OptionId::HELP, 'h', "help", false, "", "показать эту справку и завершить работу"},
    {OptionId::ALGORITHM, 'a', "algorithm", true, "ИМЯ", "алгоритм шифрования (см. список ниже)"},
    {OptionId::MODE, 'm', "mode", true, "РЕЖИМ", "encrypt, decrypt или generate-key"},
    {OptionId::KEY, 'k', "key", true, "ФАЙЛ", "прочитать ключ из файла; «-» — из стандартного ввода"},
    {OptionId::INPUT, 'i', "input", true, "ФАЙЛ", "входные данные; по умолчанию стандартный ввод"},
    {OptionId::OUTPUT, 'o', "output", true, "ФАЙЛ", "результат; по умолчанию стандартный вывод"},
    {OptionId::GENERATE_KEY, 'g', "generate-key", false, "", "при шифровании создать новый ключ"},
    {OptionId::SAVE_KEY, 's', "save-key", true, "ФАЙЛ", "сохранить созданный ключ в файл"},
    {OptionId::WRITE_KEY, 'w', "write-key", false, "", "записать созданный ключ в стандартный вывод"},
    {OptionId::KEY_LENGTH, 'n', "key-length", true, "БАЙТЫ", "длина создаваемого ключа в байтах"},
}};

const OptionSpec* find_short_option(char name) {
    const auto found = std::find_if(OPTION_SPECS.begin(), OPTION_SPECS.end(),
                                    [name](const OptionSpec& spec) { return spec.short_name == name; });
    return found == OPTION_SPECS.end() ? nullptr : &*found;
}

const OptionSpec* find_long_option(const std::string& name) {
    const auto found = std::find_if(OPTION_SPECS.begin(), OPTION_SPECS.end(),
                                    [&name](const OptionSpec& spec) { return name == spec.long_name; });
    return found == OPTION_SPECS.end() ? nullptr : &*found;
}

std::string option_label(const OptionSpec& spec) {
    return std::string("-") + spec.short_name + ", --" + spec.long_name;
}

std::size_t display_width(const std::string& utf8_text) {
    return static_cast<std::size_t>(std::count_if(utf8_text.begin(), utf8_text.end(), [](char byte) {
        return (static_cast<unsigned char>(byte) & 0xC0u) != 0x80u;
    }));
}

std::string padding_to_column(const std::string& text, std::size_t column) {
    const std::size_t width = display_width(text);
    return std::string(width < column ? column - width : 1, ' ');
}

bool is_help_argument(const std::string& argument) {
    return argument == "-h" || argument == "--help";
}

Mode parse_mode(const std::string& text) {
    if (text == "encrypt") return Mode::ENCRYPT;
    if (text == "decrypt") return Mode::DECRYPT;
    if (text == "generate-key") return Mode::GENERATE_KEY;
    throw UsageError{"Неизвестный режим «" + text + "». Допустимо: encrypt, decrypt, generate-key."};
}

std::size_t parse_key_length(const std::string& text) {
    const bool only_digits = !text.empty() && std::all_of(text.begin(), text.end(), [](char symbol) {
        return symbol >= '0' && symbol <= '9';
    });
    if (!only_digits) throw UsageError{"Длина ключа должна быть положительным целым числом."};
    std::size_t length = 0;
    for (char digit : text) {
        const auto digit_value = static_cast<std::size_t>(digit - '0');
        if (length > (std::numeric_limits<std::size_t>::max() - digit_value) / 10) {
            throw UsageError{"Слишком большая длина ключа."};
        }
        length = length * 10 + digit_value;
    }
    if (length == 0) throw UsageError{"Длина ключа должна быть больше нуля."};
    return length;
}

void store_text(std::optional<std::string>& target, const std::string& value, const OptionSpec& spec) {
    if (value.empty()) throw UsageError{"Пустое значение у параметра " + option_label(spec) + "."};
    target = value;
}

void apply_option(Options& options, const OptionSpec& spec, const std::string& value) {
    switch (spec.id) {
    case OptionId::HELP: options.show_help = true; break;
    case OptionId::ALGORITHM: options.algorithm = value; break;
    case OptionId::MODE: options.mode = parse_mode(value); break;
    case OptionId::KEY: store_text(options.key_path, value, spec); break;
    case OptionId::INPUT: store_text(options.input_path, value, spec); break;
    case OptionId::OUTPUT: store_text(options.output_path, value, spec); break;
    case OptionId::GENERATE_KEY: options.generate_key = true; break;
    case OptionId::SAVE_KEY: store_text(options.save_key_path, value, spec); break;
    case OptionId::WRITE_KEY: options.write_key = true; break;
    case OptionId::KEY_LENGTH: options.key_length = parse_key_length(value); break;
    }
}

struct ParserState {
    const std::vector<std::string>& arguments;
    std::size_t position;
    std::vector<OptionId> seen_options;
};

void accept_option(ParserState& state, Options& options, const OptionSpec& spec, const std::string& value) {
    if (std::find(state.seen_options.begin(), state.seen_options.end(), spec.id) != state.seen_options.end()) {
        throw UsageError{"Параметр " + option_label(spec) + " указан несколько раз."};
    }
    state.seen_options.push_back(spec.id);
    apply_option(options, spec, value);
}

std::string take_next_value(ParserState& state, const OptionSpec& spec) {
    if (state.position + 1 >= state.arguments.size()) {
        throw UsageError{"Для параметра " + option_label(spec) + " не указано значение."};
    }
    return state.arguments[++state.position];
}

void parse_long_option(ParserState& state, Options& options, const std::string& argument) {
    const std::string body = argument.substr(2);
    const std::size_t equals = body.find('=');
    const std::string name = body.substr(0, equals);
    const OptionSpec* spec = find_long_option(name);
    if (spec == nullptr) throw UsageError{"Неизвестный параметр «--" + name + "»."};
    if (!spec->takes_value) {
        if (equals != std::string::npos) throw UsageError{"Параметр --" + name + " не принимает значение."};
        accept_option(state, options, *spec, "");
        return;
    }
    const std::string value = equals != std::string::npos ? body.substr(equals + 1) : take_next_value(state, *spec);
    accept_option(state, options, *spec, value);
}

void parse_short_options(ParserState& state, Options& options, const std::string& argument) {
    for (std::size_t index = 1; index < argument.size(); ++index) {
        const OptionSpec* spec = find_short_option(argument[index]);
        if (spec == nullptr) throw UsageError{std::string("Неизвестный параметр «-") + argument[index] + "»."};
        if (!spec->takes_value) {
            accept_option(state, options, *spec, "");
            continue;
        }
        const std::string attached_value = argument.substr(index + 1);
        accept_option(state, options, *spec, attached_value.empty() ? take_next_value(state, *spec) : attached_value);
        return;
    }
}

}

Options parse_arguments(const std::vector<std::string>& arguments) {
    Options options;
    const bool help_requested = arguments.size() <= 1 ||
                                std::any_of(arguments.begin() + 1, arguments.end(), is_help_argument);
    if (help_requested) {
        options.show_help = true;
        return options;
    }

    ParserState state{arguments, 1, {}};
    for (; state.position < arguments.size(); ++state.position) {
        const std::string& argument = arguments[state.position];
        if (argument.size() > 2 && argument.compare(0, 2, "--") == 0) {
            parse_long_option(state, options, argument);
        } else if (argument.size() > 1 && argument[0] == '-' && argument[1] != '-') {
            parse_short_options(state, options, argument);
        } else {
            throw UsageError{"Лишний аргумент «" + argument + "». Справка: --help."};
        }
    }
    return options;
}

bool reads_standard_input(const std::optional<std::string>& path) {
    return !path.has_value() || *path == STANDARD_STREAM_ARGUMENT;
}

bool writes_standard_output(const std::optional<std::string>& path) {
    return !path.has_value() || *path == STANDARD_STREAM_ARGUMENT;
}

bool creates_key(const Options& options) {
    return options.mode == Mode::GENERATE_KEY || options.generate_key;
}

void validate_options(const Options& options) {
    if (options.algorithm.empty()) throw UsageError{"Не указан алгоритм: -a, --algorithm."};
    if (find_algorithm(options.algorithm) == nullptr) {
        throw UsageError{"Неизвестный алгоритм «" + options.algorithm + "». Список алгоритмов: --help."};
    }
    if (options.mode == Mode::NOT_SET) throw UsageError{"Не указан режим работы: -m, --mode."};

    if (creates_key(options) && !options.save_key_path && !options.write_key) {
        throw UsageError{"Создаваемый ключ некуда записать: укажите -s, --save-key или -w, --write-key."};
    }
    if (!creates_key(options) && (options.save_key_path || options.write_key || options.key_length)) {
        throw UsageError{"Параметры -s, -w и -n применяются только при создании ключа."};
    }

    if (options.mode == Mode::GENERATE_KEY) {
        if (options.generate_key || options.key_path || options.input_path || options.output_path) {
            throw UsageError{"В режиме generate-key не используются -g, -k, -i и -o."};
        }
        if (options.save_key_path && *options.save_key_path == STANDARD_STREAM_ARGUMENT) {
            throw UsageError{"Для вывода ключа в стандартный поток используйте -w, --write-key."};
        }
        return;
    }

    if (options.mode == Mode::DECRYPT && options.generate_key) {
        throw UsageError{"При расшифровании ключ не создаётся: укажите существующий ключ через -k."};
    }
    if (options.generate_key == options.key_path.has_value()) {
        throw UsageError{"Укажите ровно один источник ключа: -k, --key или -g, --generate-key."};
    }
    if (options.key_path && *options.key_path == STANDARD_STREAM_ARGUMENT && reads_standard_input(options.input_path)) {
        throw UsageError{"Ключ и данные не могут одновременно читаться из стандартного ввода: укажите -i."};
    }
    if (options.write_key && writes_standard_output(options.output_path)) {
        throw UsageError{"Ключ и результат не могут одновременно идти в стандартный вывод: укажите -o."};
    }
    if (options.save_key_path && *options.save_key_path == STANDARD_STREAM_ARGUMENT) {
        throw UsageError{"Для вывода ключа в стандартный поток используйте -w, --write-key."};
    }
}

std::string help_text(const std::string& program_name) {
    std::ostringstream text;
    text << "Multi-Algo Cryptotool — шифрование и расшифрование файлов и потоков.\n\n"
         << "Использование:\n"
         << "  " << program_name << " -a АЛГОРИТМ -m generate-key (-s ФАЙЛ | -w) [-n БАЙТЫ]\n"
         << "  " << program_name << " -a АЛГОРИТМ -m encrypt (-k ФАЙЛ | -g (-s ФАЙЛ | -w)) [-i ФАЙЛ] [-o ФАЙЛ]\n"
         << "  " << program_name << " -a АЛГОРИТМ -m decrypt -k ФАЙЛ [-i ФАЙЛ] [-o ФАЙЛ]\n"
         << "  " << program_name << " -h\n\n"
         << "Параметры:\n";
    for (const OptionSpec& spec : OPTION_SPECS) {
        std::string signature = option_label(spec);
        if (spec.takes_value) signature += std::string(" ") + spec.value_name;
        text << "  " << signature << padding_to_column(signature, 28) << spec.description << '\n';
    }
    text << "\nАлгоритмы:\n";
    for (const AlgorithmEntry& entry : SUPPORTED_ALGORITHMS) {
        text << "  " << entry.name << padding_to_column(entry.name, 10) << entry.description << '\n';
    }
    text << "\nКлючи и данные читаются и записываются как байты. Без -i данные читаются из стандартного ввода,\n"
         << "без -o результат пишется в стандартный вывод. Длина ключа по умолчанию задаётся библиотекой;\n"
         << "для vernam при -m generate-key обязателен -n, а при -g длина ключа равна длине данных.\n\n"
         << "Примеры:\n"
         << "  " << program_name << " -a table -m generate-key -s table.key\n"
         << "  " << program_name << " -a elgamal -m encrypt -k pair.key -i report.pdf -o report.pdf.enc\n"
         << "  " << program_name << " -a vernam -m encrypt -g -s pad.key -i photo.jpg -o photo.enc\n"
         << "  cat photo.enc | " << program_name << " -a vernam -m decrypt -k pad.key > photo.jpg\n";
    return text.str();
}

}
