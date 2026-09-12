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
#include "aesni.h"

uint8_t *cbc256(const uint8_t in[], uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t encrypt) {
    uint8_t *out = (uint8_t *) malloc(length * sizeof(uint8_t));
    uint8_t nextIv[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j;

    if (out == NULL)
        return NULL;

    memcpy(out, in, length);

#if TGCRYPTO_AESNI
    if (tgcrypto_aesni_available()) {
        __m128i roundKeys[15];
        __m128i ivm, next, t;

        if (encrypt)
            aes256_set_encryption_key(key, expandedKey);
        else
            aes256_set_decryption_key(key, expandedKey);

        tgcrypto_aesni_load_round_keys(expandedKey, roundKeys);

        if (encrypt) {
            ivm = _mm_loadu_si128((const __m128i *) iv);

            for (i = 0; i < length; i += AES_BLOCK_SIZE) {
                t = _mm_loadu_si128((const __m128i *) &out[i]);
                t = _mm_xor_si128(t, ivm);
                t = tgcrypto_aesni_encrypt_block(t, roundKeys);
                _mm_storeu_si128((__m128i *) &out[i], t);
                ivm = t;
            }
        } else {
            ivm = _mm_loadu_si128((const __m128i *) iv);

            for (i = 0; i < length; i += AES_BLOCK_SIZE) {
                next = _mm_loadu_si128((const __m128i *) &out[i]);
                t = tgcrypto_aesni_decrypt_block(next, roundKeys);
                t = _mm_xor_si128(t, ivm);
                _mm_storeu_si128((__m128i *) &out[i], t);
                ivm = next;
            }
        }

        _mm_storeu_si128((__m128i *) iv, ivm);

        return out;
    }
#endif

    if (encrypt) {
        aes256_set_encryption_key(key, expandedKey);

        for (i = 0; i < length; i += AES_BLOCK_SIZE) {
            for (j = 0; j < AES_BLOCK_SIZE; ++j)
                out[i + j] ^= iv[j];

            aes256_encrypt(&out[i], &out[i], expandedKey);
            memcpy(iv, &out[i], AES_BLOCK_SIZE);
        }
    } else {
        aes256_set_decryption_key(key, expandedKey);

        for (i = 0; i < length; i += AES_BLOCK_SIZE) {
            memcpy(nextIv, &out[i], AES_BLOCK_SIZE);
            aes256_decrypt(&out[i], &out[i], expandedKey);

            for (j = 0; j < AES_BLOCK_SIZE; ++j)
                out[i + j] ^= iv[j];

            memcpy(iv, nextIv, AES_BLOCK_SIZE);
        }
    }

    return out;
}
