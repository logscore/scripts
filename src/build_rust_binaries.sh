#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME=$(grep '^name = ' Cargo.toml 2>/dev/null | sed 's/name = "\(.*\)"/\1/' || echo "myapp")
OUTPUT_DIR="dist"
TARGETS=("x86_64-unknown-linux-musl" "aarch64-unknown-linux-musl" "x86_64-apple-darwin" "aarch64-apple-darwin")
ZIG_VERSION="0.16.0"
BUILD_LOG="build_errors.log"

clean_up() {
    if [ -f "$BUILD_LOG" ]; then rm -f "$BUILD_LOG"; fi
}

RED="\033[0;31m"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

command -v cargo &>/dev/null || { echo "Error: cargo not found"; exit 1; }

if [[ "$OSTYPE" == "linux"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "Error: Unsupported OS $OSTYPE"
    exit 1
fi

if ! command -v zig &>/dev/null; then
    echo -e "${YELLOW}Installing zig...${NC}"
    if [[ "$OS" == "macos" ]]; then
        brew install zig >/dev/null 2>&1
    elif [[ "$OS" == "linux" ]]; then
        ARCH=$(uname -m)
        [[ "$ARCH" == "x86_64" || "$ARCH" == "aarch64" ]] || { echo "Error: Unsupported arch"; exit 1; }

        INSTALL_DIR="$HOME/.local"
        BIN_DIR="$INSTALL_DIR/bin"
        mkdir -p "$BIN_DIR"

        TEMP_DIR=$(mktemp -d)
        curl -sL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${ARCH}-${ZIG_VERSION}.tar.xz" | tar -xJf - -C "$TEMP_DIR"
        mv "$TEMP_DIR/zig-linux-${ARCH}-${ZIG_VERSION}" "$INSTALL_DIR/zig"
        ln -sf "$INSTALL_DIR/zig/zig" "$BIN_DIR/zig"

        [[ ":$PATH:" != *":$BIN_DIR:"* ]] && export PATH="$BIN_DIR:$PATH"
        rm -rf "$TEMP_DIR"
    fi
else
    echo -e "${GREEN}✓${NC} zig [installed]"
fi

if ! command -v cargo-zigbuild &>/dev/null; then
    echo -e "${YELLOW}Installing cargo-zigbuild...${NC}"
    cargo install cargo-zigbuild -q 2>/dev/null || { echo "Error: cargo install failed"; exit 1; }
else
    echo -e "${GREEN}✓${NC} cargo-zigbuild [installed]"
fi
echo "Starting build..."

for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed 2>/dev/null | grep -q "^${target}$"; then
        echo -n "Adding target $target... "
        if rustup target add "$target" >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}SKIP${NC}"
        fi
    fi

    echo -n "Compiling $target... "

    if cargo zigbuild --release --target "$target" --quiet 2>"$BUILD_LOG"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e " ${RED}FAILED${NC}"
        cat "$BUILD_LOG"
        exit 1
    fi

    SRC="target/${target}/release/${PROJECT_NAME}"
    DEST="${OUTPUT_DIR}/${target}/${PROJECT_NAME}"

    mkdir -p "${OUTPUT_DIR}/${target}"
    cp "$SRC" "$DEST"
done

clean_up
echo -e "${GREEN}Build complete.${NC}"
