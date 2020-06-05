#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#endif 

// #define IOCTL_ALLOC_SHELLCODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define IOCTL_RELEASE_SHELLCODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define IOCTL_COPY_SHELLCODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define IOCTL_EXECUTE_SHELLCODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ALLOC_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_COPY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPRAY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNSPRAY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct ioctl_arb_primitive{
	size_t size;
	uintptr_t where;
	char what[1];
} ioctl_arb_primitive_t;

typedef struct ioctl_alloc{
	size_t alloc_size;
	POOL_TYPE pooltype;
	int tag;
} ioctl_alloc_t;

typedef struct ioctl_copy{
	size_t buffer_size;
	char * data;
} ioctl_copy_t;

typedef struct ioctl_spray{
	size_t alloc_size;
	size_t nb_allocs;
	POOL_TYPE pooltype;
	int tag;
	char what[1];
} ioctl_spray_t;

typedef struct spray_s
{
	size_t spray_index;
	size_t nb_allocs;
	size_t alloc_size;
	POOL_TYPE pooltype;
	int 	tag;
	void * allocs[1];
} spray_t;
