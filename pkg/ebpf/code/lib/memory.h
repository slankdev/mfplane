/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright 2022 Hiroki Shirokura.
 * Copyright 2022 Wide Project.
 */

#ifndef _MEMORY_H_
#define _MEMORY_H_

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif
#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

#endif /* _MEMORY_H_ */
