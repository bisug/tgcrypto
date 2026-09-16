# TgCrypto

> [!NOTE]
> This is a maintained fork of [pyrogram/tgcrypto](https://github.com/pyrogram/tgcrypto).
> It keeps the original API fully compatible and adds modernized packaging, support for
> Python 3.9–3.14, and optional AES-NI hardware acceleration (see
> [Performance](#performance)).

> [!NOTE]
> The implementations of the algorithms presented in this repository are to be considered for educational purposes only.

> Fast and Portable Cryptography Extension Library for Pyrogram

**TgCrypto** is a Cryptography Library written in C as a Python extension. It is designed to be portable, fast,
easy to install and use. TgCrypto is intended for [Pyrogram](https://github.com/pyrogram/pyrogram) and implements the
cryptographic algorithms Telegram requires, namely:

- **`AES-256-IGE`** - used in [MTProto v2.0](https://core.telegram.org/mtproto).
- **`AES-256-CTR`** - used for [CDN encrypted files](https://core.telegram.org/cdn).
- **`AES-256-CBC`** - used for [encrypted passport credentials](https://core.telegram.org/passport).

## Requirements

- Python 3.9 or higher.
- A C compiler (the extension is compiled from source).

## Installation

``` bash
$ pip3 install -U git+https://github.com/bisug/tgcrypto
```

## Performance

On x86/x86-64 CPUs with AES-NI support, the library automatically uses
hardware-accelerated AES instructions, detected once at runtime. On every other
platform (or CPU without AES-NI) it falls back to the portable software
implementation. Both paths produce bit-for-bit identical output.

To build without the hardware acceleration path, define `TGCRYPTO_NO_AESNI`:

``` bash
$ CFLAGS="-DTGCRYPTO_NO_AESNI" pip3 install git+https://github.com/bisug/tgcrypto
```

For a maximum-speed local build (GCC/Clang only), opt in to heavier
optimization — kept out of the default build so the MSVC Windows wheels keep
working:

``` bash
$ CFLAGS="-O3 -flto" pip3 install git+https://github.com/bisug/tgcrypto
```

Note the portable table-based AES implementation is functionally correct but
not hardened against cache-timing side channels; the AES-NI path
(constant-time instructions, used automatically when available) is preferred.

Per-call overhead matters as much as bulk throughput: MTProto encrypts many
small messages (a 16-byte payload is a single AES block), so the fixed cost of
every call — argument handling, key schedule and the key-material wipe —
dominates at that size. Two further optimizations target that fixed cost:

* **Key-material wipe** (expanded key plus loaded round keys, ~500 bytes per
  call) is cleared with word-wide stores instead of a byte-wise volatile loop,
  which is ~8x cheaper while giving exactly the same guarantee.
* **Key schedule** — on the AES-NI path the 60-word expanded key is generated
  with `aeskeygenassist`/`aesimc` instructions instead of the table-based
  scalar routine, and the round keys are consumed directly from it. The scalar
  schedule cost ~445 ns per call (encrypt) and ~630 ns (decrypt) on the
  reference machine; the instruction-based one is a small fraction of that.
* **No redundant copy** — the AES-NI paths read the input buffer directly
  instead of first copying it into the output buffer, so large payloads are
  touched once rather than twice.

Indicative, on a low-power Celeron N4120 with the AES-NI path active (best of
5, one C call, so no Python overhead included):

| Operation | Before | After |
|---|---|---|
| AES-256-IGE encrypt, 16 B | 1742 ns | **984 ns** |
| AES-256-IGE decrypt, 16 B | 1407 ns | **559 ns** |
| AES-256-CTR encrypt, 16 B | 1401 ns | **713 ns** |
| AES-256-IGE encrypt, 1 KiB | 4692 ns | **3510 ns** |

The gain is per call, so it is largest for small messages (1.8–3x at a single
block) and tapers off for large buffers (about 1.3–1.5x at 1 KiB), where AES
throughput dominates instead.

Measured throughput of the Python API before/after the key-schedule and
copy changes (same machine, alternating runs, best of 2 rounds, MB/s):

| Operation | Size | Before | After | Change |
|---|---|---|---|---|
| IGE encrypt | 16 B | 10 | 14 | +30% |
| IGE decrypt | 16 B | 8 | 13 | +60% |
| CBC decrypt | 16 B | 6 | 10 | +48% |
| CBC encrypt | 16 B | 8 | 10 | +20% |
| CTR encrypt | 16 B | 7 | 8 | +21% |
| CBC decrypt | 1 KiB | 233 | 294 | +26% |
| CTR encrypt | 1 KiB | 228 | 252 | +11% |
| CBC decrypt | 1 MiB | 598 | 736 | +23% |
| CTR encrypt | 1 MiB | 500 | 606 | +21% |
| CBC encrypt | 1 MiB | 338 | 382 | +13% |
| IGE encrypt/decrypt | 64 KiB – 1 MiB | 374–379 | 373–379 | ~0% |

IGE on large buffers is deliberately unchanged: with a serial feedback chain
each block depends on the previous one, so the mode is bound by AES round
latency rather than throughput and no amount of key-schedule tuning helps.
For bulk MTProto traffic (which is IGE) that is the ceiling on this class of
CPU — the AES-NI path is already within ~2x of OpenSSL's raw AES-CTR while
also doing the IGE chaining.

## Comparison with the original

| | Original ([pyrogram/tgcrypto](https://github.com/pyrogram/tgcrypto)) | This fork |
|---|---|---|
| Status | Unmaintained | Actively maintained |
| Python support | 3.7 – 3.11 | **3.9 – 3.14** |
| Packaging | `setup.py` | `pyproject.toml` (PEP 621) |
| AES acceleration | Portable software implementation only | **AES-NI hardware acceleration** (runtime-detected) with software fallback |
| Speed on AES-NI CPUs | Baseline | ~**4–6× faster** for IGE/CTR on large buffers |
| Speed without AES-NI / non-x86 | — | Identical (same software code path, bit-for-bit) |
| Output compatibility | — | Cryptographic output is **bit-for-bit identical** to the original |
| API | Six functions | **Unchanged** — drop-in compatible |
| CI | — | Test matrix 3.9–3.14; wheels built for Linux (x86_64, ARM64), macOS (Intel, Apple Silicon) and Windows |
| License | LGPLv3+ | LGPLv3+ |

Indicative benchmark (AES-NI, 16 MB buffers, best of 5):

| Operation | Original | This fork |
|---|---|---|
| AES-256-IGE encrypt | 59 MB/s | 247 MB/s |
| AES-256-CTR encrypt | 46 MB/s | 284 MB/s |

Actual gains scale with CPU speed. On CPUs without AES-NI (or when built with
`TGCRYPTO_NO_AESNI`), performance matches the original exactly, since the same
software code path is used.

## API

TgCrypto API consists of these six methods:

```python
def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...

def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes: ...
def ctr256_decrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes: ...

def cbc256_encrypt(data: bytes, key: bytes, iv: bytearray) -> bytes: ...
def cbc256_decrypt(data: bytes, key: bytes, iv: bytearray) -> bytes: ...
```

> **Buffer semantics (MTProto streaming):** `ige256_*` copies the 32-byte IV
> into local state, so read-only `bytes` are fine. `ctr256_*` mutates the
> 16-byte counter `iv` and the 1-byte `state` in place, and `cbc256_*` mutates
> the 16-byte `iv` to the last block — so those must be **writable**
> (`bytearray`/`memoryview`). Immutable `bytes` there raises `BufferError`
> instead of corrupting memory. Don't share one `iv`/`state` across threads.

## Usage

### IGE Mode

**Note**: Data must be padded to match a multiple of the block size (16 bytes).

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024 + 7)  # 10 MB of random data + 7 bytes to show padding
key = os.urandom(32)  # Random Key
iv = os.urandom(32)  # Random IV

# Pad with zeroes: -7 % 16 = 9
data += bytes(-len(data) % 16)

ige_encrypted = tgcrypto.ige256_encrypt(data, key, iv)
ige_decrypted = tgcrypto.ige256_decrypt(ige_encrypted, key, iv)

print(data == ige_decrypted)  # True
```
    
### CTR Mode (single chunk)

Prefer chunk sizes up to ~1 MiB for large inputs: peak transient memory is
about 1x the chunk size (the output buffer), and chunking keeps streaming
state (`iv`, `state`) moving as documented above.

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024)  # 10 MB of random data

key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

ctr_encrypted = tgcrypto.ctr256_encrypt(data, key, enc_iv, bytearray(1))
ctr_decrypted = tgcrypto.ctr256_decrypt(ctr_encrypted, key, dec_iv, bytearray(1))

print(data == ctr_decrypted)  # True
```

### CTR Mode (stream)

``` python
import os
from io import BytesIO

import tgcrypto

data = BytesIO(os.urandom(10 * 1024 * 1024))  # 10 MB of random data

key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

enc_state = bytearray(1)  # Encryption state, starts from 0
dec_state = bytearray(1)  # Decryption state, starts from 0

encrypted_data = BytesIO()  # Encrypted data buffer
decrypted_data = BytesIO()  # Decrypted data buffer

while True:
    chunk = data.read(1024)

    if not chunk:
        break

    # Write 1K encrypted bytes into the encrypted data buffer
    encrypted_data.write(tgcrypto.ctr256_encrypt(chunk, key, enc_iv, enc_state))

# Reset position. We need to read it now
encrypted_data.seek(0)

while True:
    chunk = encrypted_data.read(1024)

    if not chunk:
        break

    # Write 1K decrypted bytes into the decrypted data buffer
    decrypted_data.write(tgcrypto.ctr256_decrypt(chunk, key, dec_iv, dec_state))

print(data.getvalue() == decrypted_data.getvalue())  # True
```

### CBC Mode

**Note**: Data must be padded to match a multiple of the block size (16 bytes).

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024 + 7)  # 10 MB of random data + 7 bytes to show padding
key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

# Pad with zeroes: -7 % 16 = 9
data += bytes(-len(data) % 16)

cbc_encrypted = tgcrypto.cbc256_encrypt(data, key, enc_iv)
cbc_decrypted = tgcrypto.cbc256_decrypt(cbc_encrypted, key, dec_iv)

print(data == cbc_decrypted)  # True
```

## MTProto 2.0 boundary

`tgcrypto` implements only the raw AES primitives MTProto 2.0 needs
(`AES-256-IGE` for cloud chats, `AES-256-CTR` for CDN files, `AES-256-CBC`
for Passport). The surrounding protocol — `msg_key` derivation
(`SHA256(authKey[88+x:88+x+32] || plaintext)[8:24]`, `x=0`/`x=8`), KDF into
`aes_key`/`aes_iv`, padding `12..1024` bytes, `msg_id`/`seqno` checks,
RSA/DH handshake, SRP 2FA — belongs in the client layer (e.g. Pyrogram),
not here. `ige256_decrypt` does not verify `msg_key`; callers must.

## Testing

1. Clone this repository: `git clone https://github.com/bisug/tgcrypto`.
2. Enter the directory: `cd tgcrypto`.
3. Install the test dependencies: `pip3 install pytest pycryptodome cryptography`
   (`pycryptodome`/`cryptography` are used as independent reference primitives by
   the known-answer tests; without them those tests skip silently.)
4. Run tests: `pytest`.

## License

[LGPLv3+](COPYING.lesser) © 2017-present [Dan](https://github.com/delivrance)

Modifications in this fork are released under the same license.
