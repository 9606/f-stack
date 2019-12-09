/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2019 Jan Sucan <jansucan@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * FreeBSD
 */

#ifndef UTILS_H
#define UTILS_H 1

#include <sys/types.h>

#ifdef	__LP64__
typedef	__uint64_t	__uintptr_t;
typedef	__int64_t	__register_t;
#else
typedef	__uint32_t	__uintptr_t;
typedef	__int32_t	__register_t;
#endif

#define	_ALIGNBYTES	(sizeof(__register_t) - 1)
#define	_ALIGN(p)	(((__uintptr_t)(p) + _ALIGNBYTES) & ~_ALIGNBYTES)

/* Operations on timespecs */
#define    timespecclear(tvp)    ((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#define    timespecisset(tvp)    ((tvp)->tv_sec || (tvp)->tv_nsec)
#define    timespeccmp(tvp, uvp, cmp)                    \
    (((tvp)->tv_sec == (uvp)->tv_sec) ?                \
        ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :            \
        ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define    timespecadd(tsp, usp, vsp)                    \
    do {                                \
        (vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;        \
        (vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;    \
        if ((vsp)->tv_nsec >= 1000000000L) {            \
            (vsp)->tv_sec++;                \
            (vsp)->tv_nsec -= 1000000000L;            \
        }                            \
    } while (0)
#define    timespecsub(tsp, usp, vsp)                    \
    do {                                \
        (vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;        \
        (vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;    \
        if ((vsp)->tv_nsec < 0) {                \
            (vsp)->tv_sec--;                \
            (vsp)->tv_nsec += 1000000000L;            \
        }                            \
    } while (0)

u_short in_cksum(u_char *, int);

#endif