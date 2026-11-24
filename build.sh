#!/bin/sh
set -xe

CFLAGS="-Wall -Wextra -pedantic -ggdb -Iinclude"

mkdir -p build
cc $CFLAGS main.c src/*.c -o build/sapler
