#!/bin/bash
nasm -f elf64 -o oligomorph.o oligomorph.s
ld -o oligomorph oligomorph.o
rm target*
for i in `seq 1 10`; do ./oligomorph ; cat target > target_$i; sleep 1; done
for i in `seq 1 10`; do hexdump target_$i; done
rm target*
