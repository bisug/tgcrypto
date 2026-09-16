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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef AES256_H
#define AES256_H

#define AES_BLOCK_SIZE 16
#define EXPANDED_KEY_SIZE 60

void aes256_set_encryption_key(const uint8_t key[32], uint32_t expandedKey[60]);

void aes256_set_decryption_key(const uint8_t key[32], uint32_t expandedKey[60]);

void aes256_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]);

void aes256_decrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]);

/*
 * Best-effort memory wipe for key material. Written through a volatile
 * pointer so the compiler cannot optimize the wipe away.
 *
 * Whole words are cleared whenever the pointer is suitably aligned. A
 * byte-wise volatile loop costs ~1.7 ns per byte, and the key schedules and
 * round keys wiped on every call add up to ~500 bytes, which is a measurable
 * share of a small encrypt/decrypt call. Clearing 4 bytes per store is
 * roughly 8x cheaper for exactly the same guarantee.
 */
static inline void tgcrypto_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *) p;

    /* Bring the pointer up to a 4-byte boundary (at most 3 bytes). */
    while (n != 0 && (((uintptr_t) v) & 3) != 0) {
        *v++ = 0;
        --n;
    }

    while (n >= 4) {
        *(volatile uint32_t *) v = 0;
        v += 4;
        n -= 4;
    }

    while (n != 0) {
        *v++ = 0;
        --n;
    }
}

#endif  // AES256_H
