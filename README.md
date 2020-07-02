This repository contains a PoC exploit using an exploitation technique called Aligned Chunk Confusion.
The details on the technique can be found in the [paper](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion/blob/master/Scoop_The_Windows_10_pool.pdf).

This exploit leverages a heap overflow in the Windows kernel heap to elevate its privileges from Low to SYSTEM.


# The research

The goal of the research was to develop a generic exploit for a heap overflow vulnerability in the kernel Pool.

When exploiting a heap overflow, the size of the vulnerable object (the one overflowing) is important, since it will have an impact on where and how it's allocated. Also, the type of pool where it will be allocated is relevant for the same reasons.

That's why, to be generic, the exploit must:

- work in both PagedPool and NonPagedPoolNx, the two main pool types
- work with any size of vulnerable chunk (under 0xff0)

The presented exploit can work in both PagedPool and NonPagedPool ; it uses similar techniques with different objects.


# The exploit


The exploited vulnerability is not a real one, and is constructed with a driver exposing a fully controlled heap overflow.

The exploit is a PoC and isn't perfectly stable. It mostly works with size from 0x130 to 0x300, but it could be adapted to work with any size.
The stability of the exploit can also be greatly improved by using better heap massaging techniques.

## Compiling the vulnerable driver

The driver can be compiled with Visual studio, using the solution in Driver.

## Compiling the exploit

A makefile can compile the whole exploit written in C.

It depends on gcc-mingw-w64-x86-64.


```
make
```

It can be compiled in debug mode, that will add checks using the driver and more verbose output.

```
make debug
```


# Presentations

This work has been presented at [SSTIC 2020](https://www.sstic.org/2020/presentation/pool_overflow_exploitation_since_windows_10_19h1/) and at [OPCDE 8](https://github.com/comaeio/OPCDE/tree/master/2020/July/1).
The slides for both presentations are available [here](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion/blob/master/slides.pdf).
