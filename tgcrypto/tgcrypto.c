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

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <limits.h>
#include <stdint.h>

#include "aes256.h"
#include "ige256.h"
#include "ctr256.h"
#include "cbc256.h"

#define TGCRYPTO_VERSION "1.2.5"

#define DESCRIPTION "Fast and Portable Cryptography Extension Library for Pyrogram\n" \
    "TgCrypto is part of Pyrogram, a Telegram MTProto library for Python\n" \
    "You can learn more about Pyrogram here: https://pyrogram.org\n"

static void release3(Py_buffer *a, Py_buffer *b, Py_buffer *c) {
    PyBuffer_Release(a);
    PyBuffer_Release(b);
    PyBuffer_Release(c);
}

static void release4(Py_buffer *a, Py_buffer *b, Py_buffer *c, Py_buffer *d) {
    PyBuffer_Release(a);
    PyBuffer_Release(b);
    PyBuffer_Release(c);
    PyBuffer_Release(d);
}

static PyObject *ige(PyObject *args, uint8_t encrypt) {
    Py_buffer data, key, iv;
    PyObject *out;
    Py_ssize_t n;

    if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
        return NULL;

    if (data.len == 0) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (data.len % 16 != 0) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "Data size must match a multiple of 16 bytes");
        return NULL;
    }

    if (key.len != 32) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 32) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 32 bytes");
        return NULL;
    }

    /* Compare as uint64_t: casting UINT32_MAX to Py_ssize_t wraps to -1 on
     * 32-bit platforms, which would reject every input. */
    if ((uint64_t) data.len > (uint64_t) UINT32_MAX) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "Data is too large (max 4294967295 bytes)");
        return NULL;
    }

    /* IGE copies the IV into local state, so read-only buffers are fine. */
    n = data.len;
    out = PyBytes_FromStringAndSize(NULL, n);

    if (out == NULL) {
        release3(&data, &key, &iv);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        ige256(data.buf, (uint8_t *) PyBytes_AS_STRING(out), (uint32_t) n, key.buf, iv.buf, encrypt);
    Py_END_ALLOW_THREADS

    release3(&data, &key, &iv);

    return out;
}

static PyObject *ige256_encrypt(PyObject *self, PyObject *args) {
    return ige(args, 1);
}

static PyObject *ige256_decrypt(PyObject *self, PyObject *args) {
    return ige(args, 0);
}

static PyObject *ctr(PyObject *args) {
    Py_buffer data, key, iv, state;
    PyObject *out;
    Py_ssize_t n;

    if (!PyArg_ParseTuple(args, "y*y*y*y*", &data, &key, &iv, &state))
        return NULL;

    if (data.len == 0) {
        release4(&data, &key, &iv, &state);
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (key.len != 32) {
        release4(&data, &key, &iv, &state);
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 16) {
        release4(&data, &key, &iv, &state);
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 16 bytes");
        return NULL;
    }

    if (state.len != 1) {
        release4(&data, &key, &iv, &state);
        PyErr_SetString(PyExc_ValueError, "State size must be exactly 1 byte");
        return NULL;
    }

    if (*(uint8_t *) state.buf > 15) {
        release4(&data, &key, &iv, &state);
        PyErr_SetString(PyExc_ValueError, "State value must be in the range [0, 15]");
        return NULL;
    }

    /* CTR mutates the counter IV and the keystream offset in place so the
     * caller can resume streaming. Writing into immutable bytes would be
     * undefined behaviour, so require writable buffers. */
    if (iv.readonly || state.readonly) {
        release4(&data, &key, &iv, &state);
        PyErr_SetString(PyExc_BufferError,
                        "IV and state must be writable buffers (e.g. bytearray), "
                        "they are updated in place for streaming");
        return NULL;
    }

    if ((uint64_t) data.len > (uint64_t) UINT32_MAX) {
        release4(&data, &key, &iv, &state);
        PyErr_SetString(PyExc_ValueError, "Data is too large (max 4294967295 bytes)");
        return NULL;
    }

    n = data.len;
    out = PyBytes_FromStringAndSize(NULL, n);

    if (out == NULL) {
        release4(&data, &key, &iv, &state);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        ctr256(data.buf, (uint8_t *) PyBytes_AS_STRING(out), (uint32_t) n, key.buf, iv.buf, state.buf);
    Py_END_ALLOW_THREADS

    release4(&data, &key, &iv, &state);

    return out;
}

static PyObject *ctr256_encrypt(PyObject *self, PyObject *args) {
    return ctr(args);
}

static PyObject *ctr256_decrypt(PyObject *self, PyObject *args) {
    /* CTR encryption and decryption are the same XOR operation. */
    return ctr(args);
}

static PyObject *cbc(PyObject *args, uint8_t encrypt) {
    Py_buffer data, key, iv;
    PyObject *out;
    Py_ssize_t n;

    if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
        return NULL;

    if (data.len == 0) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (data.len % 16 != 0) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "Data size must match a multiple of 16 bytes");
        return NULL;
    }

    if (key.len != 32) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 16) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 16 bytes");
        return NULL;
    }

    if ((uint64_t) data.len > (uint64_t) UINT32_MAX) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_ValueError, "Data is too large (max 4294967295 bytes)");
        return NULL;
    }

    /* CBC chains the IV through the message (it ends holding the last block),
     * so the IV must be a writable buffer. */
    if (iv.readonly) {
        release3(&data, &key, &iv);
        PyErr_SetString(PyExc_BufferError,
                        "IV must be a writable buffer (e.g. bytearray), "
                        "it is updated in place");
        return NULL;
    }

    n = data.len;
    out = PyBytes_FromStringAndSize(NULL, n);

    if (out == NULL) {
        release3(&data, &key, &iv);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        cbc256(data.buf, (uint8_t *) PyBytes_AS_STRING(out), (uint32_t) n, key.buf, iv.buf, encrypt);
    Py_END_ALLOW_THREADS

    release3(&data, &key, &iv);

    return out;
}

static PyObject *cbc256_encrypt(PyObject *self, PyObject *args) {
    return cbc(args, 1);
}

static PyObject *cbc256_decrypt(PyObject *self, PyObject *args) {
    return cbc(args, 0);
}

PyDoc_STRVAR(
    ige256_encrypt_docs,
    "ige256_encrypt(data, key, iv)\n"
    "--\n\n"
    "AES-256-IGE Encryption"
);

PyDoc_STRVAR(
    ige256_decrypt_docs,
    "ige256_decrypt(data, key, iv)\n"
    "--\n\n"
    "AES-256-IGE Decryption"
);

PyDoc_STRVAR(
    ctr256_encrypt_docs,
    "ctr256_encrypt(data, key, iv, state)\n"
    "--\n\n"
    "AES-256-CTR Encryption.\n"
    "``iv`` and ``state`` must be writable buffers (e.g. bytearray):\n"
    "they are updated in place so encryption can be resumed chunk by chunk."
);

PyDoc_STRVAR(
    ctr256_decrypt_docs,
    "ctr256_decrypt(data, key, iv, state)\n"
    "--\n\n"
    "AES-256-CTR Decryption.\n"
    "``iv`` and ``state`` must be writable buffers (e.g. bytearray):\n"
    "they are updated in place so decryption can be resumed chunk by chunk."
);

PyDoc_STRVAR(
    cbc256_encrypt_docs,
    "cbc256_encrypt(data, key, iv)\n"
    "--\n\n"
    "AES-256-CBC Encryption.\n"
    "``iv`` must be a writable buffer (e.g. bytearray):\n"
    "it is updated in place to the last ciphertext block."
);

PyDoc_STRVAR(
    cbc256_decrypt_docs,
    "cbc256_decrypt(data, key, iv)\n"
    "--\n\n"
    "AES-256-CBC Decryption.\n"
    "``iv`` must be a writable buffer (e.g. bytearray):\n"
    "it is updated in place to the last ciphertext block."
);

static PyMethodDef methods[] = {
    {"ige256_encrypt", (PyCFunction) ige256_encrypt, METH_VARARGS, ige256_encrypt_docs},
    {"ige256_decrypt", (PyCFunction) ige256_decrypt, METH_VARARGS, ige256_decrypt_docs},
    {"ctr256_encrypt", (PyCFunction) ctr256_encrypt, METH_VARARGS, ctr256_encrypt_docs},
    {"ctr256_decrypt", (PyCFunction) ctr256_decrypt, METH_VARARGS, ctr256_decrypt_docs},
    {"cbc256_encrypt", (PyCFunction) cbc256_encrypt, METH_VARARGS, cbc256_encrypt_docs},
    {"cbc256_decrypt", (PyCFunction) cbc256_decrypt, METH_VARARGS, cbc256_decrypt_docs},
    {NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "TgCrypto",
    DESCRIPTION,
    -1,
    methods
};

PyMODINIT_FUNC PyInit_tgcrypto(void) {
    PyObject *m = PyModule_Create(&module);

    if (m == NULL)
        return NULL;

    if (PyModule_AddStringConstant(m, "__version__", TGCRYPTO_VERSION) < 0) {
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
