#!/bin/bash

# These binaries are suitable for Debian-based distros
# might need adjustments for others
OBJCOPY=x86_64-w64-mingw32-objcopy
GCC=x86_64-w64-mingw32-gcc

SIZE=$1
OUTFILE=$2

# create empty file
dd if=/dev/zero of=zeros.bin bs=1000000 count=$SIZE

$OBJCOPY -I binary -O pe-x86-64 -B i386:x86-64 zeros.bin zeros.o
cp zeros.bin zeros2.bin
$OBJCOPY -I binary -O pe-x86-64 -B i386:x86-64 zeros2.bin zeros2.o
$GCC -mcmodel=large -Wl,--image-base -Wl,0x10000000 -c stub.c
$GCC -o $OUTFILE -mcmodel=large -Wl,--image-base -Wl,0x10000000 zeros.o zeros2.o stub.o

# clean up
rm zeros.bin zeros2.bin zeros.o zeros2.o stub.o
