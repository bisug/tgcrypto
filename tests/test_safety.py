# Safety regression tests: writable IV/state enforcement, error-path buffer
# handling, and module metadata.
import os
import unittest

import tgcrypto


class TestWritableBuffers(unittest.TestCase):
    KEY = bytes.fromhex(
        "603DEB1015CA71BE2B73AEF0857D7781"
        "1F352C073B6108D72D9810A30914DFF4"
    )

    def test_ctr_rejects_immutable_iv(self):
        with self.assertRaises(BufferError):
            tgcrypto.ctr256_encrypt(b"0123456789ABCDEF", self.KEY,
                                    bytes(16), bytearray(1))

    def test_ctr_rejects_immutable_state(self):
        with self.assertRaises(BufferError):
            tgcrypto.ctr256_encrypt(b"0123456789ABCDEF", self.KEY,
                                    bytearray(16), bytes(1))

    def test_ctr_decrypt_rejects_immutable_iv(self):
        with self.assertRaises(BufferError):
            tgcrypto.ctr256_decrypt(b"0123456789ABCDEF", self.KEY,
                                    bytes(16), bytearray(1))

    def test_cbc_rejects_immutable_iv(self):
        with self.assertRaises(BufferError):
            tgcrypto.cbc256_encrypt(bytes(16), self.KEY, bytes(16))

    def test_cbc_decrypt_rejects_immutable_iv(self):
        with self.assertRaises(BufferError):
            tgcrypto.cbc256_decrypt(bytes(16), self.KEY, bytes(16))

    def test_ige_accepts_immutable_iv(self):
        # IGE copies the IV into local state: read-only input must keep working.
        data = os.urandom(32)
        key = os.urandom(32)
        iv = os.urandom(32)
        out = tgcrypto.ige256_encrypt(data, key, iv)
        self.assertEqual(tgcrypto.ige256_decrypt(out, key, iv), data)


class TestErrorPathsDoNotLeakBuffers(unittest.TestCase):
    def test_repeated_validation_failures(self):
        # Buffers must be released on every error path; hammer them and make
        # sure the interpreter stays usable (previously leaked buffer locks).
        for _ in range(1000):
            with self.assertRaises(ValueError):
                tgcrypto.ige256_encrypt(b"", os.urandom(32), os.urandom(32))
            with self.assertRaises(ValueError):
                tgcrypto.ige256_encrypt(os.urandom(16), os.urandom(31), os.urandom(32))
            with self.assertRaises(ValueError):
                tgcrypto.ctr256_encrypt(b"", os.urandom(32), bytearray(16), bytearray(1))
            with self.assertRaises(ValueError):
                tgcrypto.ctr256_encrypt(os.urandom(8), os.urandom(32),
                                        bytearray(15), bytearray(1))
            with self.assertRaises(ValueError):
                tgcrypto.cbc256_encrypt(bytes(15), os.urandom(32), bytearray(16))
            with self.assertRaises(ValueError):
                tgcrypto.ctr256_encrypt(os.urandom(8), os.urandom(32),
                                        bytearray(16), bytes([16]))
            with self.assertRaises(BufferError):
                tgcrypto.ctr256_encrypt(os.urandom(8), os.urandom(32),
                                        bytes(16), bytearray(1))
            with self.assertRaises(BufferError):
                tgcrypto.cbc256_encrypt(bytes(16), os.urandom(32), bytes(16))


class TestStreamingMutation(unittest.TestCase):
    def test_ctr_stream_matches_oneshot(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            self.skipTest("cryptography package required for reference vector")

        key = os.urandom(32)
        iv0 = os.urandom(16)
        data = os.urandom(1000)

        encryptor = Cipher(algorithms.AES(key), modes.CTR(iv0)).encryptor()
        expected = encryptor.update(data) + encryptor.finalize()

        enc_iv = bytearray(iv0)
        enc_state = bytearray(1)
        got = b"".join(
            tgcrypto.ctr256_encrypt(data[i:i + 100], key, enc_iv, enc_state)
            for i in range(0, len(data), 100)
        )
        self.assertEqual(got, expected)


        dec_iv = bytearray(iv0)
        dec_state = bytearray(1)
        back = b"".join(
            tgcrypto.ctr256_decrypt(got[i:i + 100], key, dec_iv, dec_state)
            for i in range(0, len(got), 100)
        )
        self.assertEqual(back, data)

    def test_cbc_iv_chains_to_last_block(self):
        key = os.urandom(32)
        data = os.urandom(64)
        iv = bytearray(os.urandom(16))
        out = tgcrypto.cbc256_encrypt(data, key, iv)
        # CBC leaves the IV holding the last ciphertext block for chaining.
        self.assertEqual(bytes(iv), out[-16:])
        start = bytearray(os.urandom(16))
        dec_iv = bytearray(start)
        first = tgcrypto.cbc256_encrypt(data[:32], key, dec_iv)
        second = tgcrypto.cbc256_encrypt(data[32:], key, dec_iv)
        combined = tgcrypto.cbc256_encrypt(data, key, bytearray(start))
        self.assertEqual(first + second, combined)
        self.assertEqual(
            tgcrypto.cbc256_decrypt(combined, key, bytearray(start)), data)


class TestIGEKnownAnswer(unittest.TestCase):
    # Hand-verifiable KAT for the software fallback: single-block IGE must
    # equal plain AES-ECB wrapped in the IGE chaining XORs:
    #   C = AES(P ^ IV1) ^ IV2 ; P = AES^-1(C ^ IV1) ^ IV2
    # validated here with ECB from PyCryptodome as the independent primitive.
    def test_ige_single_block_matches_ecb_construction(self):
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            self.skipTest("pycryptodome required for IGE reference vector")
        key = bytes.fromhex(
            "000102030405060708090A0B0C0D0E0F"
            "101112131415161718191A1B1C1D1E1F"
        )
        iv = bytes.fromhex(
            "000102030405060708090A0B0C0D0E0F"
            "101112131415161718191A1B1C1D1E1F"
        )
        plaintext = bytes.fromhex(
            "00112233445566778899AABBCCDDEEFF"
            "102233445566778899AABBCCDDEEFF00"
        )
        # Block 0: C0 = ECB(P0 ^ IV1) ^ IV2.
        iv1, iv2 = iv[:16], iv[16:]
        ecb = AES.new(key, AES.MODE_ECB)
        xored = bytes(a ^ b for a, b in zip(plaintext[:16], iv1))
        c0 = bytes(a ^ b for a, b in zip(ecb.encrypt(xored), iv2))
        # Block 1 chains: C1 = ECB(P1 ^ C0) ^ P0.
        xored1 = bytes(a ^ b for a, b in zip(plaintext[16:], c0))
        c1 = bytes(a ^ b for a, b in zip(ecb.encrypt(xored1), plaintext[:16]))
        ref = c0 + c1
        self.assertEqual(tgcrypto.ige256_encrypt(plaintext, key, iv), ref)
        self.assertEqual(tgcrypto.ige256_decrypt(ref, key, iv), plaintext)

    def test_ige_multiblock_diffusion(self):
        key = os.urandom(32)
        iv = os.urandom(32)
        zeros = bytes(64)
        ct = tgcrypto.ige256_encrypt(zeros, key, iv)
        self.assertNotEqual(ct[:16], ct[16:32])
        self.assertEqual(tgcrypto.ige256_decrypt(ct, key, iv), zeros)


class TestEdgeLengths(unittest.TestCase):
    # Lock in the CTR counter/state arithmetic around block and unroll
    # boundaries (single-byte, exact blocks, 4x-unroll edges, odd tails).
    LENGTHS = [1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129,
               1000, 1024, 1025]

    def test_ctr_edge_lengths_roundtrip_all_states(self):
        key = os.urandom(32)
        for n in self.LENGTHS:
            for s in (0, 1, 7, 15):
                data = os.urandom(n)
                iv0 = os.urandom(16)
                enc_iv, dec_iv = bytearray(iv0), bytearray(iv0)
                enc_state, dec_state = bytearray([s]), bytearray([s])
                ct = tgcrypto.ctr256_encrypt(data, key, enc_iv, enc_state)
                self.assertEqual(
                    tgcrypto.ctr256_decrypt(ct, key, dec_iv, dec_state), data)

    def test_ige_cbc_edge_block_counts(self):
        key = os.urandom(32)
        for blocks in (1, 2, 3, 4, 5, 63, 64, 65):
            n = blocks * 16
            data = os.urandom(n)
            iv32 = os.urandom(32)
            self.assertEqual(
                tgcrypto.ige256_decrypt(
                    tgcrypto.ige256_encrypt(data, key, iv32), key, iv32), data)
            start = os.urandom(16)
            ct = tgcrypto.cbc256_encrypt(data, key, bytearray(start))
            self.assertEqual(
                tgcrypto.cbc256_decrypt(ct, key, bytearray(start)), data)


class TestModuleMetadata(unittest.TestCase):
    def test_version_matches(self):
        self.assertEqual(tgcrypto.__version__, "1.2.5")

    def test_ctr_decrypt_is_own_function(self):
        self.assertEqual(tgcrypto.ctr256_decrypt.__name__, "ctr256_decrypt")


if __name__ == "__main__":
    unittest.main()
