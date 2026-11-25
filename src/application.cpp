#include "application.h"

#include "command_line.h"
#include "crypto_service.h"
#include "platform.h"
#include "plugin_loader.h"
#include "byte_stream.h"
#include "stream_io.h"

#include <iostream>
#include <stdexcept>

namespace cryptotool {

namespace {

constexpr std::size_t MAX_STORED_KEY_SIZE = 64 * 1024;

std::string program_name(const std::vector<std::string>& arguments) {
    if (arguments.empty()) return "cryptotool";
    return path_to_utf8(path_from_utf8(arguments.front()).filename());
}

std::size_t requested_key_length(const Options& options, const AlgorithmModule& module) {
    if (options.key_length) return *options.key_length;
    if (module.info->key_size == 0) {
        throw UsageError{"Для алгоритма " + options.algorithm + " укажите длину ключа: -n, --key-length."};
    }
    return module.info->key_size;
}

struct KeyOutputs {
    OutputStream saved_key;
    std::vector<std::ostream*> streams;
};

KeyOutputs open_key_outputs(const Options& options) {
    KeyOutputs outputs;
    if (options.save_key_path) {
        outputs.saved_key = open_output_stream(options.save_key_path, FileAccess::OWNER_ONLY);
        outputs.streams.push_back(outputs.saved_key.stream);
    }
    if (options.write_key) outputs.streams.push_back(&std::cout);
    return outputs;
}

void commit_key_outputs(KeyOutputs& outputs, const Options& options) {
    if (options.save_key_path) commit_output(outputs.saved_key);
    if (options.write_key) std::cout.flush();
    if (!std::cout) throw std::runtime_error("Ошибка записи ключа в стандартный вывод.");
}

void run_key_generation(const Options& options, const AlgorithmModule& module) {
    const std::size_t key_length = requested_key_length(options, module);
    KeyOutputs outputs = open_key_outputs(options);
    if (uses_keystream(module)) {
        generate_keystream(module, key_length, outputs.streams);
    } else {
        const SecureBytes key = generate_fixed_key(module, key_length);
        for (std::ostream* stream : outputs.streams) write_bytes(*stream, key.data(), key.size());
    }
    commit_key_outputs(outputs, options);
}

KeyMaterial prepare_key(const Options& options, const AlgorithmModule& module, KeyOutputs& key_outputs,
                        InputStream& key_input) {
    KeyMaterial key;
    if (options.generate_key) {
        if (uses_keystream(module)) {
            if (options.key_length) throw UsageError{"Для алгоритма " + options.algorithm + " длина ключа равна длине данных, -n не нужен."};
            key.generate_keystream = true;
            key.generated_key_outputs = key_outputs.streams;
        } else {
            key.fixed_key = generate_fixed_key(module, requested_key_length(options, module));
            for (std::ostream* stream : key_outputs.streams) write_bytes(*stream, key.fixed_key.data(), key.fixed_key.size());
        }
        return key;
    }
    key_input = open_input_stream(options.key_path, "файл ключа");
    if (uses_keystream(module)) {
        key.keystream_input = key_input.stream;
    } else {
        key.fixed_key = read_key_bytes(*key_input.stream, MAX_STORED_KEY_SIZE);
    }
    return key;
}

void run_transformation(const Options& options, const AlgorithmModule& module) {
    require_distinct_files(options.input_path, options.output_path, "Входной и выходной файлы должны различаться.");
    require_distinct_files(options.save_key_path, options.input_path, "Ключ нельзя сохранить поверх входного файла.");
    require_distinct_files(options.save_key_path, options.output_path, "Ключ и результат должны быть разными файлами.");
    require_distinct_files(options.key_path, options.output_path, "Результат нельзя записать поверх файла ключа.");

    const Operation operation = options.mode == Mode::ENCRYPT ? Operation::ENCRYPT : Operation::DECRYPT;
    InputStream data_input = open_input_stream(options.input_path, "входной файл");
    InputStream key_input;
    KeyOutputs key_outputs = open_key_outputs(options);
    KeyMaterial key = prepare_key(options, module, key_outputs, key_input);
    OutputStream data_output = open_output_stream(options.output_path, FileAccess::SHARED);

    transform_stream(module, operation, key, *data_input.stream, *data_output.stream);

    commit_key_outputs(key_outputs, options);
    commit_output(data_output);
}

}

int run_application(const std::vector<std::string>& arguments) {
    try {
        const Options options = parse_arguments(arguments);
        if (options.show_help) {
            std::cout << help_text(program_name(arguments));
            return EXIT_CODE_SUCCESS;
        }
        validate_options(options);

        set_standard_streams_binary();
        const AlgorithmEntry& entry = *find_algorithm(options.algorithm);
        const auto loaded = load_algorithm(entry, executable_directory(arguments.front()));
        if (options.mode == Mode::GENERATE_KEY) {
            run_key_generation(options, loaded->module);
        } else {
            run_transformation(options, loaded->module);
        }
        return EXIT_CODE_SUCCESS;
    } catch (const UsageError& error) {
        std::cerr << "Ошибка: " << error.message << "\nСправка: " << program_name(arguments) << " --help\n";
        return EXIT_CODE_USAGE_ERROR;
    } catch (const std::bad_alloc&) {
        std::cerr << "Ошибка: недостаточно оперативной памяти.\n";
    } catch (const std::filesystem::filesystem_error& error) {
        std::cerr << "Ошибка файловой системы: " << error.what() << '\n';
    } catch (const std::exception& error) {
        std::cerr << "Ошибка: " << error.what() << '\n';
    }
    return EXIT_CODE_FAILURE;
}

}
