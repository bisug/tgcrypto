/*
 * Pyrogram - Telegram MTProto API Client Library for Python
 * Copyright (C) 2017-present Dan <https://github.com/delivrance>
 *
 * This file is part of Pyrogram.
 *
 * Pyrogram is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pyrogram is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "aes256.h"

#ifndef TGCRYPTO_AESNI_H
#define TGCRYPTO_AESNI_H

/*
 * Optional AES-NI acceleration for x86/x86-64.
 *
 * The pure software implementation remains the default and the fallback:
 * - On non-x86 targets (e.g. arm64) nothing from this header is compiled in.
 * - CPU support is detected at runtime; without hardware support the
 *   software code paths are used.
 * - Defining TGCRYPTO_NO_AESNI (e.g. CFLAGS="-DTGCRYPTO_NO_AESNI") always
 *   compiles out the hardware path entirely.
 */

#if (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)) && \
    !defined(TGCRYPTO_NO_AESNI) && \
    (defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER))
#define TGCRYPTO_AESNI 1
#endif

#if TGCRYPTO_AESNI

#include <wmmintrin.h>
#include <tmmintrin.h>
#include <emmintrin.h>

#if defined(_MSC_VER)
#include <intrin.h>
#define TGCRYPTO_AESNI_TARGET
#else
#define TGCRYPTO_AESNI_TARGET __attribute__((target("aes,ssse3"), unused))
#endif

/*
 * Round keys are loaded straight from the standard 60-word expanded key
 * buffers produced by aes256_set_encryption_key() /
 * aes256_set_decryption_key(). The decryption buffer already holds the
 * equivalent inverse cipher form (reversed order, middle rounds transformed
 * with the inverse MixColumns), which is exactly what the aesdec round
 * instructions expect, so no additional key preparation is needed.
 */

static TGCRYPTO_AESNI_TARGET int tgcrypto_aesni_available(void) {
    static int cached = -1;

    if (cached < 0) {
#if defined(_MSC_VER)
        int info[4];

        __cpuid(info, 1);
        cached = (info[2] >> 25) & 1;
#else
        cached = __builtin_cpu_supports("aes") ? 1 : 0;
#endif
    }

    return cached;
}

static TGCRYPTO_AESNI_TARGET void tgcrypto_aesni_load_round_keys(const uint32_t expandedKey[60], __m128i roundKeys[15]) {
    /*
     * The expanded key words are packed big-endian, so their in-memory byte
     * order is reversed on little-endian machines. The AES-NI round
     * instructions consume the round key as raw AES state bytes, therefore
     * every 4-byte group must be byte-swapped while loading. (All CPUs with
     * AES-NI also have SSSE3, which provides the byte-shuffle instruction.)
     */
    const __m128i bswap_mask = _mm_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
    );
    int i;

    for (i = 0; i < 15; ++i)
        roundKeys[i] = _mm_shuffle_epi8(
            _mm_loadu_si128((const __m128i *) &expandedKey[4 * i]), bswap_mask
        );
}

static TGCRYPTO_AESNI_TARGET __m128i tgcrypto_aesni_encrypt_block(__m128i block, const __m128i roundKeys[15]) {
    int i;

    block = _mm_xor_si128(block, roundKeys[0]);

    for (i = 1; i < 14; ++i)
        block = _mm_aesenc_si128(block, roundKeys[i]);

    return _mm_aesenclast_si128(block, roundKeys[14]);
}

static TGCRYPTO_AESNI_TARGET __m128i tgcrypto_aesni_decrypt_block(__m128i block, const __m128i roundKeys[15]) {
    int i;

    block = _mm_xor_si128(block, roundKeys[0]);

    for (i = 1; i < 14; ++i)
        block = _mm_aesdec_si128(block, roundKeys[i]);

    return _mm_aesdeclast_si128(block, roundKeys[14]);
}

/*
 * AES-NI key expansion.
 *
 * Produces exactly the same 60 expanded-key words as the software
 * aes256_set_encryption_key() / aes256_set_decryption_key(), but without any
 * table lookups. For decryption the round keys are transformed with aesimc
 * (inverse MixColumns) and emitted in reverse order - the equivalent inverse
 * cipher layout the scalar code builds (dec[0] = K14, dec[i] = InvMix(K(14-i)),
 * dec[14] = K0), which is exactly what aesdec expects.
 *
 * aesenc/aesdec consume a round key as raw AES state bytes, so the words are
 * byte-swapped per 4-byte group on the way out - the exact inverse of
 * tgcrypto_aesni_load_round_keys().
 *
 * On a low-power Celeron N4120 the scalar schedule costs ~445 ns (encrypt) and
 * ~630 ns (decrypt) per call, i.e. roughly a third of a one-block IGE call,
 * while this version replaces it with a handful of AES instructions.
 */
static TGCRYPTO_AESNI_TARGET void tgcrypto_aesni_expand_key(const uint8_t key[32], uint32_t expandedKey[60],
                                                            uint8_t decrypt) {
    const __m128i bswap_mask = _mm_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
    );
    __m128i rk[15];
    __m128i lo, hi, t;
    int i;

    lo = _mm_loadu_si128((const __m128i *) key);
    hi = _mm_loadu_si128((const __m128i *) (key + 16));

#define TGCRYPTO_AESNI_NEXT_LO(rcon)                   \
    t = _mm_aeskeygenassist_si128(hi, rcon);           \
    t = _mm_shuffle_epi32(t, 0xFF);                    \
    lo = _mm_xor_si128(lo, _mm_slli_si128(lo, 4));     \
    lo = _mm_xor_si128(lo, _mm_slli_si128(lo, 4));     \
    lo = _mm_xor_si128(lo, _mm_slli_si128(lo, 4));     \
    lo = _mm_xor_si128(lo, t)
#define TGCRYPTO_AESNI_NEXT_HI()                       \
    t = _mm_aeskeygenassist_si128(lo, 0x00);           \
    t = _mm_shuffle_epi32(t, 0xAA);                    \
    hi = _mm_xor_si128(hi, _mm_slli_si128(hi, 4));     \
    hi = _mm_xor_si128(hi, _mm_slli_si128(hi, 4));     \
    hi = _mm_xor_si128(hi, _mm_slli_si128(hi, 4));     \
    hi = _mm_xor_si128(hi, t)

    rk[0] = lo;
    rk[1] = hi;

    TGCRYPTO_AESNI_NEXT_LO(0x01); rk[2] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[3] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x02); rk[4] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[5] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x04); rk[6] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[7] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x08); rk[8] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[9] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x10); rk[10] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[11] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x20); rk[12] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[13] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x40); rk[14] = lo;

#undef TGCRYPTO_AESNI_NEXT_LO
#undef TGCRYPTO_AESNI_NEXT_HI

    if (decrypt) {
        for (i = 1; i < 14; ++i)
            rk[i] = _mm_aesimc_si128(rk[i]);

        for (i = 0; i < 7; ++i) {
            t = rk[i];
            rk[i] = rk[14 - i];
            rk[14 - i] = t;
        }
    }

    for (i = 0; i < 15; ++i)
        _mm_storeu_si128((__m128i *) &expandedKey[4 * i], _mm_shuffle_epi8(rk[i], bswap_mask));

    tgcrypto_wipe(rk, sizeof(rk));
}

#endif  // TGCRYPTO_AESNI

#endif  // TGCRYPTO_AESNI_H
