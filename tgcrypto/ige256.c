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

void ige256(const uint8_t in[], uint8_t out[], uint32_t length, const uint8_t key[32], const uint8_t iv[32],
            uint8_t encrypt) {
    uint8_t iv1[AES_BLOCK_SIZE], iv2[AES_BLOCK_SIZE];
    uint8_t chunk[AES_BLOCK_SIZE], buffer[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j;

    memcpy(encrypt ? iv1 : iv2, (uint8_t *) iv, AES_BLOCK_SIZE);
    memcpy(encrypt ? iv2 : iv1, (uint8_t *) iv + AES_BLOCK_SIZE, AES_BLOCK_SIZE);

#if TGCRYPTO_AESNI
    if (tgcrypto_aesni_available())
        tgcrypto_aesni_expand_key(key, expandedKey, (uint8_t) (encrypt ? 0 : 1));
    else
#endif
        (encrypt ? aes256_set_encryption_key : aes256_set_decryption_key)(key, expandedKey);

#if TGCRYPTO_AESNI
    if (tgcrypto_aesni_available()) {
        __m128i roundKeys[15];
        __m128i x, iv1m, iv2m, t;

        tgcrypto_aesni_load_round_keys(expandedKey, roundKeys);
        iv1m = _mm_loadu_si128((const __m128i *) iv1);
        iv2m = _mm_loadu_si128((const __m128i *) iv2);

        if (encrypt) {
            for (i = 0; i < length; i += AES_BLOCK_SIZE) {
                x = _mm_loadu_si128((const __m128i *) &in[i]);
                t = _mm_xor_si128(x, iv1m);
                t = tgcrypto_aesni_encrypt_block(t, roundKeys);
                t = _mm_xor_si128(t, iv2m);
                _mm_storeu_si128((__m128i *) &out[i], t);
                iv1m = t;
                iv2m = x;
            }
        } else {
            for (i = 0; i < length; i += AES_BLOCK_SIZE) {
                x = _mm_loadu_si128((const __m128i *) &in[i]);
                t = _mm_xor_si128(x, iv1m);
                t = tgcrypto_aesni_decrypt_block(t, roundKeys);
                t = _mm_xor_si128(t, iv2m);
                _mm_storeu_si128((__m128i *) &out[i], t);
                iv1m = t;
                iv2m = x;
            }
        }

        tgcrypto_wipe(roundKeys, sizeof(roundKeys));
        tgcrypto_wipe(iv1, sizeof(iv1));
        tgcrypto_wipe(iv2, sizeof(iv2));
        tgcrypto_wipe(expandedKey, sizeof(expandedKey));

        return;
    }
#endif

    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        memcpy(chunk, &in[i], AES_BLOCK_SIZE);

        for (j = 0; j < AES_BLOCK_SIZE; ++j)
            buffer[j] = in[i + j] ^ iv1[j];

        (encrypt ? aes256_encrypt : aes256_decrypt)((uint8_t * ) & buffer, &out[i], expandedKey);

        for (j = 0; j < AES_BLOCK_SIZE; ++j)
            out[i + j] ^= iv2[j];

        memcpy(iv1, &out[i], AES_BLOCK_SIZE);
        memcpy(iv2, chunk, AES_BLOCK_SIZE);
    }

    tgcrypto_wipe(iv1, sizeof(iv1));
    tgcrypto_wipe(iv2, sizeof(iv2));
    tgcrypto_wipe(chunk, sizeof(chunk));
    tgcrypto_wipe(buffer, sizeof(buffer));
    tgcrypto_wipe(expandedKey, sizeof(expandedKey));
}
