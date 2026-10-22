.DEFAULT_GOAL := all

CC := gcc
TARGET := output/filecrypt

SOURCES := src/filecrypt.c src/main.c
HEADERS := src/filecryptHead.h

CFLAGS := -Wall -Wextra -Wpedantic -O2 -Isrc
CPPFLAGS := $(shell pkg-config --cflags openssl)
LDLIBS := $(shell pkg-config --libs openssl)

.PHONY: all build clean check-deps

all: check-deps build

check-deps:
	@command -v gcc >/dev/null 2>&1 || { echo "Error: gcc is not installed."; exit 1; }
	@command -v pkg-config >/dev/null 2>&1 || { echo "Error: pkg-config is not installed."; exit 1; }
	@pkg-config --exists openssl || { echo "Error: OpenSSL development files are missing."; exit 1; }

build: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	@mkdir -p output
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)