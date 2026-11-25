# Multi-Algo Cryptotool

Консольная программа для шифрования и расшифрования файлов и потоков. Алгоритмы вынесены в динамические библиотеки:

| Алгоритм  | Библиотека (Linux / Windows)  | Ключ |
|-----------|-------------------------------|------|
| `elgamal` | `libelgamal.so` / `elgamal.dll` | 512 байт: открытый `y` (256) и закрытый `x` (256). Для шифрования достаточно первых 256 байт |
| `table`   | `libtable.so` / `table.dll`     | N байт-меток столбцов 1..N без повторов, 2 ≤ N ≤ 255, по умолчанию 16 |
| `vernam`  | `libvernam.so` / `vernam.dll`   | случайные байты, длина ключа равна длине данных |

## Сборка

Нужны компилятор C++17 (GCC ≥ 9.1, Clang ≥ 10, MinGW-w64 или MSVC ≥ 19.20) и OpenSSL 3 (libcrypto).

Linux (Debian/Ubuntu: `sudo apt install g++ make cmake pkg-config libssl-dev`):

```sh
make            # программа, библиотеки и утилита тестов в build/bin
make test       # запустить тесты
make clean
```

или через CMake:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build      # или build/bin/cryptotool_tests
```

Windows (MinGW-w64): заголовки и библиотека OpenSSL для x64 лежат в `deps`, CMake и Makefile находят их сами.

```bat
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
```

Предупреждения компилятора считаются ошибками (`-Werror`, `/WX`).

## Установка

Linux: `sudo scripts/install.sh` копирует программу и библиотеки в `/opt/cryptotool` и создаёт ссылку `/usr/local/bin/cryptotool`. Удаление: `sudo scripts/uninstall.sh`.

Windows: запустите `scripts\install.bat` от имени администратора. Файлы копируются в `C:\Program Files\Cryptotool`, каталог добавляется в системную переменную `Path`. Удаление: `scripts\uninstall.bat`.

## Использование

```
cryptotool -a АЛГОРИТМ -m generate-key (-s ФАЙЛ | -w) [-n БАЙТЫ]
cryptotool -a АЛГОРИТМ -m encrypt (-k ФАЙЛ | -g (-s ФАЙЛ | -w)) [-i ФАЙЛ] [-o ФАЙЛ]
cryptotool -a АЛГОРИТМ -m decrypt -k ФАЙЛ [-i ФАЙЛ] [-o ФАЙЛ]
cryptotool -h
```

| Короткий | Длинный | Назначение |
|----------|---------|------------|
| `-h` | `--help` | справка; имеет приоритет над остальными параметрами |
| `-a` | `--algorithm` | `elgamal`, `table` или `vernam` |
| `-m` | `--mode` | `encrypt`, `decrypt` или `generate-key` |
| `-k` | `--key` | файл ключа; `-` — стандартный ввод |
| `-i` | `--input` | входной файл; по умолчанию стандартный ввод |
| `-o` | `--output` | выходной файл; по умолчанию стандартный вывод |
| `-g` | `--generate-key` | создать ключ при шифровании |
| `-s` | `--save-key` | сохранить созданный ключ в файл |
| `-w` | `--write-key` | вывести созданный ключ в стандартный вывод |
| `-n` | `--key-length` | длина создаваемого ключа в байтах |

Без аргументов программа печатает справку. Значение можно писать через пробел (`-a table`, `--algorithm table`) или через `=` (`--algorithm=table`).

Примеры:

```sh
cryptotool -a table -m generate-key -s table.key
cryptotool -a table -m encrypt -k table.key -i report.pdf -o report.pdf.enc
cryptotool -a table -m decrypt -k table.key -i report.pdf.enc -o report.pdf

cryptotool -a elgamal -m generate-key -s pair.key
head -c 256 pair.key > public.key            # открытый ключ для отправителя
tar -czf - docs | cryptotool -a elgamal -m encrypt -k public.key -o docs.tar.gz.enc
cat docs.tar.gz.enc | cryptotool -a elgamal -m decrypt -k pair.key | tar -xzf -

cryptotool -a vernam -m encrypt -g -s video.key -i lecture.mp4 -o lecture.enc
cryptotool -a vernam -m decrypt -k video.key -i lecture.enc -o lecture.mp4
cryptotool -a vernam -m generate-key -n 32 -w | base64 > key.txt
cryptotool -a vernam -m decrypt -k <(base64 -d key.txt) -i data.enc -o data.bin
```

В PowerShell открытый ключ Эль-Гамаля выделяется так:
`$b = [IO.File]::ReadAllBytes('pair.key'); [IO.File]::WriteAllBytes('public.key', $b[0..255])`.

Коды завершения: `0` — успех, `1` — ошибка выполнения (нет файла, нет прав, неверный ключ, повреждённые данные, нет библиотеки), `2` — ошибка в аргументах.

## Устройство

```
include/crypto_plugin_api.h   C ABI библиотек: ConstBuffer, MutBuffer, AlgorithmInfo, коды ошибок
src/main.cpp                  точка входа
src/application.cpp           сценарии режимов: генерация ключа, шифрование, расшифрование
src/command_line.cpp          разбор и проверка аргументов, справка
src/crypto_service.cpp        бизнес-логика: потоковая обработка блоками по 1 МиБ
src/algorithm_module.h        таблица функций алгоритма, от которой зависит бизнес-логика
src/plugin_loader.cpp         список алгоритмов, имена библиотек, загрузка
src/stream_io.cpp             файлы и стандартные потоки, запись через временный файл
src/byte_stream.cpp           чтение и запись байтов в потоки
src/platform.cpp              код для Linux и Windows: консоль, аргументы, dlopen/LoadLibrary, очистка памяти
src/secure_memory.h           аллокатор, затирающий память перед освобождением
plugins/<алгоритм>/           реализации алгоритмов
tests/plugin_tests.cpp        утилита тестирования библиотек
scripts/                      установщики и деинсталляторы
```

Каждая библиотека экспортирует `get_algorithm_info`, `get_output_size`, `generate_key`, `encrypt`, `decrypt`. Библиотека Эль-Гамаля дополнительно экспортирует `encrypt_with_nonce`, она нужна только для тестов. Память под результат выделяет программа по размеру из `get_output_size`. Исключения не выходят за границу библиотеки: функции возвращают код из `CryptoStatus`. Буферы с ключами и данными затираются перед освобождением (`explicit_bzero`, `SecureZeroMemory`, `OPENSSL_cleanse`).

Данные обрабатываются кусками по 1 МиБ, поэтому для файла любого размера нужно около 15 МБ памяти. Эль-Гамаль шифрует блоки по 254 байта с дополнением PKCS#7 до целого числа блоков; каждый блок даёт 512 байт шифротекста, случайный показатель `k` генерируется внутри библиотеки для каждого блока. Табличная перестановка и Вернам сохраняют длину данных.

Сборка и тесты проверены на Linux x86_64 (GCC 13, Clang 18, OpenSSL 3.0). Код для Windows в этой среде не компилировался: перед сдачей соберите проект в MinGW или MSVC.

Ключи в примерах служат только для проверки. Табличная перестановка — учебный шифр без современной стойкости. Эль-Гамаль реализован без аутентификации. Ключ Вернама должен быть случайным, секретным и использоваться один раз.
