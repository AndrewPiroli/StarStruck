# SFFS host tool - builds a PC utility to read/write Wii NAND SFFS images.

CC      := cc
CFLAGS  := -O2 -g -Wall -Wextra -std=gnu11 -Iinclude -Isrc/host -Isrc
LDFLAGS :=

SRnand := \
	src/sffs/cache.c \
	src/sffs/commands.c \
	src/sffs/filesystem.c \
	src/sffs/inode.c \
	src/errors.c

SRC_HOST := \
	src/host/crypto.c \
	src/host/keys.c \
	src/host/nandimage.c \
	src/host/nand.c \
	src/host/cluster.c \
	src/host/endian.c \
	src/host/main.c

SRCS := $(SRnand) $(SRC_HOST)
OBJS := $(SRCS:.c=.o)

TARGET := sffs

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
