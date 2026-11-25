#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR=/opt/cryptotool
LINK_PATH=/usr/local/bin/cryptotool
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build/bin"

if [[ $EUID -ne 0 ]]; then
    echo "Установка требует прав администратора: sudo $0" >&2
    exit 1
fi

if [[ ! -x "$SOURCE_DIR/cryptotool" ]]; then
    echo "Программа не собрана: выполните make или cmake --build build в каталоге проекта." >&2
    exit 1
fi

for library in libelgamal.so libtable.so libvernam.so; do
    if [[ ! -f "$SOURCE_DIR/$library" ]]; then
        echo "Не найдена библиотека $SOURCE_DIR/$library" >&2
        exit 1
    fi
done

install -d -m 755 "$INSTALL_DIR"
install -m 755 "$SOURCE_DIR/cryptotool" "$INSTALL_DIR/cryptotool"
install -m 644 "$SOURCE_DIR"/libelgamal.so "$SOURCE_DIR"/libtable.so "$SOURCE_DIR"/libvernam.so "$INSTALL_DIR/"

install -d -m 755 "$(dirname "$LINK_PATH")"
ln -sfn "$INSTALL_DIR/cryptotool" "$LINK_PATH"

echo "Установлено в $INSTALL_DIR, команда: cryptotool"
