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

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

uint8_t *ctr256(const uint8_t in[], uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t *state) {
    uint8_t *out = (uint8_t *) malloc(length * sizeof(uint8_t));
    uint8_t chunk[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j, k;

    if (out == NULL)
        return NULL;

    memcpy(out, in, length);
    aes256_set_encryption_key(key, expandedKey);

#if TGCRYPTO_AESNI
    if (tgcrypto_aesni_available()) {
        __m128i roundKeys[15];
        __m128i ks0, ks1, ks2, ks3, c0, c1, c2, c3, x;
        __m128i keystream;
        uint32_t processed = 0;

        tgcrypto_aesni_load_round_keys(expandedKey, roundKeys);

        if (*state == 0) {
            while (length - processed >= 4 * AES_BLOCK_SIZE) {
                c0 = _mm_loadu_si128((const __m128i *) iv);
                k = AES_BLOCK_SIZE;
                while (k--)
                    if (++iv[k])
                        break;

                c1 = _mm_loadu_si128((const __m128i *) iv);
                k = AES_BLOCK_SIZE;
                while (k--)
                    if (++iv[k])
                        break;

                c2 = _mm_loadu_si128((const __m128i *) iv);
                k = AES_BLOCK_SIZE;
                while (k--)
                    if (++iv[k])
                        break;

                c3 = _mm_loadu_si128((const __m128i *) iv);
                k = AES_BLOCK_SIZE;
                while (k--)
                    if (++iv[k])
                        break;

                ks0 = tgcrypto_aesni_encrypt_block(c0, roundKeys);
                ks1 = tgcrypto_aesni_encrypt_block(c1, roundKeys);
                ks2 = tgcrypto_aesni_encrypt_block(c2, roundKeys);
                ks3 = tgcrypto_aesni_encrypt_block(c3, roundKeys);

                x = _mm_loadu_si128((const __m128i *) &out[processed]);
                _mm_storeu_si128((__m128i *) &out[processed], _mm_xor_si128(x, ks0));

                x = _mm_loadu_si128((const __m128i *) &out[processed + AES_BLOCK_SIZE]);
                _mm_storeu_si128((__m128i *) &out[processed + AES_BLOCK_SIZE], _mm_xor_si128(x, ks1));

                x = _mm_loadu_si128((const __m128i *) &out[processed + 2 * AES_BLOCK_SIZE]);
                _mm_storeu_si128((__m128i *) &out[processed + 2 * AES_BLOCK_SIZE], _mm_xor_si128(x, ks2));

                x = _mm_loadu_si128((const __m128i *) &out[processed + 3 * AES_BLOCK_SIZE]);
                _mm_storeu_si128((__m128i *) &out[processed + 3 * AES_BLOCK_SIZE], _mm_xor_si128(x, ks3));

                processed += 4 * AES_BLOCK_SIZE;
            }

            while (processed + AES_BLOCK_SIZE <= length) {
                c0 = _mm_loadu_si128((const __m128i *) iv);
                ks0 = tgcrypto_aesni_encrypt_block(c0, roundKeys);
                x = _mm_loadu_si128((const __m128i *) &out[processed]);
                _mm_storeu_si128((__m128i *) &out[processed], _mm_xor_si128(x, ks0));

                k = AES_BLOCK_SIZE;
                while (k--)
                    if (++iv[k])
                        break;

                processed += AES_BLOCK_SIZE;
            }
        }

        if (processed < length) {
            keystream = tgcrypto_aesni_encrypt_block(_mm_loadu_si128((const __m128i *) iv), roundKeys);
            _mm_storeu_si128((__m128i *) chunk, keystream);

            for (i = processed; i < length; ++i) {
                out[i] ^= chunk[(*state)++];

                if (*state >= AES_BLOCK_SIZE) {
                    *state = 0;

                    k = AES_BLOCK_SIZE;
                    while (k--)
                        if (++iv[k])
                            break;

                    keystream = tgcrypto_aesni_encrypt_block(_mm_loadu_si128((const __m128i *) iv), roundKeys);
                    _mm_storeu_si128((__m128i *) chunk, keystream);
                }
            }
        }

        return out;
    }
#endif

    aes256_encrypt(iv, chunk, expandedKey);

    for (i = 0; i < length; i += AES_BLOCK_SIZE)
        for (j = 0; j < MIN(length - i, AES_BLOCK_SIZE); ++j) {
            out[i + j] ^= chunk[(*state)++];

            if (*state >= AES_BLOCK_SIZE)
                *state = 0;

            if (*state == 0) {
                k = AES_BLOCK_SIZE;
                while(k--)
                    if (++iv[k])
                        break;

                aes256_encrypt(iv, chunk, expandedKey);
            }
        }

    return out;
}
