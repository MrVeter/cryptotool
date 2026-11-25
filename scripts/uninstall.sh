#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR=/opt/cryptotool
LINK_PATH=/usr/local/bin/cryptotool

if [[ $EUID -ne 0 ]]; then
    echo "Удаление требует прав администратора: sudo $0" >&2
    exit 1
fi

if [[ -L "$LINK_PATH" && "$(readlink "$LINK_PATH")" == "$INSTALL_DIR/cryptotool" ]]; then
    rm -f "$LINK_PATH"
fi

if [[ -d "$INSTALL_DIR" ]]; then
    rm -f "$INSTALL_DIR/cryptotool" "$INSTALL_DIR/libelgamal.so" "$INSTALL_DIR/libtable.so" "$INSTALL_DIR/libvernam.so"
    rmdir "$INSTALL_DIR" 2>/dev/null || echo "В $INSTALL_DIR остались посторонние файлы, каталог не удалён." >&2
fi

echo "Multi-Algo Cryptotool удалён."
