# SPDX-License-Identifier: 0BSD
# Author: Lasse Collin

CC = cc
CFLAGS = -g -m32
LDFLAGS = -llzma -lssl -lcrypto -static

PROGS = mpcimg2

all: $(PROGS)

# Build Rust version (default)
mpcimg2:
	cargo build --release
	cp target/release/mpcimg2 mpcimg2

# Build C version (if needed)
mpcimg2-c: mpcimg2.c
	$(CC) $(CFLAGS) -o mpcimg2-c mpcimg2.c $(LDFLAGS)

.c:
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	-rm -f $(PROGS) mpcimg2-c
	-cargo clean

.PHONY: all clean
