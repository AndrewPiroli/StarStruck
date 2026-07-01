/*
	SFFS host tool - base type definitions.

	Host (PC) replacement for the StarStruck <types.h>. Provides the u8..s64
	typedefs and the CHECK_SIZE / CHECK_OFFSET compile-time asserts that the
	SFFS sources rely on, without pulling in any of the IOS-specific bits.
*/

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef volatile uint8_t vu8;
typedef volatile uint16_t vu16;
typedef volatile uint32_t vu32;
typedef volatile uint64_t vu64;

typedef volatile int8_t vs8;
typedef volatile int16_t vs16;
typedef volatile int32_t vs32;
typedef volatile int64_t vs64;

/* NOTE: on the host we deliberately use the real <stddef.h> size_t rather than
   redefining it to u32 (which the on-device build does). SFFS never stores a
   size_t on NAND, so this only matters for local variables. */

#ifdef __cplusplus
#define StaticAssert static_assert
#else
#define StaticAssert _Static_assert
#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

#define ALIGNED(x) __attribute__((aligned(x)))

#define ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

#define CHECK_SIZE(Type, Size) StaticAssert(sizeof(Type) == (Size), #Type " must be " #Size " bytes")

#define CHECK_OFFSET(Type, Offset, Field) \
	StaticAssert(offsetof(Type, Field) == (Offset), #Type "::" #Field " must be at offset " #Offset)
