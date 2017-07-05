#ifndef gimli_H
#define gimli_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wlong-long"
#endif
extern "C" {
#endif

#ifndef __GNUC__
#ifdef __attribute__
#undef __attribute__
#endif
#define __attribute__(a)
#endif

typedef struct gimli_hash_state {
    uint32_t state[12];
    uint8_t  buf_off;
    uint8_t  align_0;
    uint8_t  out_len;
    uint8_t  align_1;
} gimli_hash_state;

#define gimli_hash_BYTES 32
#define gimli_hash_BYTES_MAX 65535
#define gimli_hash_BYTES_MIN 16
#define gimli_hash_CONTEXTBYTES 8
#define gimli_hash_KEYBYTES 32
#define gimli_hash_KEYBYTES_MAX 32
#define gimli_hash_KEYBYTES_MIN 16

int gimli_hash_init(gimli_hash_state *state,
                    const char ctx[gimli_hash_CONTEXTBYTES],
                    const uint8_t *key, size_t key_len);

int gimli_hash_init_with_tweak(gimli_hash_state *state,
                               const char ctx[gimli_hash_CONTEXTBYTES],
                               uint64_t tweak, const uint8_t *key,
                               size_t key_len);

int gimli_hash_update(gimli_hash_state *state, const void *in_, size_t in_len);

int gimli_hash_final(gimli_hash_state *state, uint8_t *out, size_t out_len);

/* ---------------- */

#define gimli_kdf_CONTEXTBYTES 8
#define gimli_kdf_KEYBYTES 32
#define gimli_kdf_BYTES_MAX 65535
#define gimli_kdf_BYTES_MIN 16

int gimli_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len,
                              uint64_t      subkey_id,
                              const char    ctx[gimli_kdf_CONTEXTBYTES],
                              const uint8_t key[gimli_kdf_KEYBYTES]);

/* ---------------- */

#define gimli_secretbox_CONTEXTBYTES 8
#define gimli_secretbox_HEADERBYTES (20 + 16)
#define gimli_secretbox_KEYBYTES 32
#define gimli_secretbox_IVBYTES 20

int
gimli_secretbox_encrypt_iv(uint8_t *c, const void *m_, size_t mlen,
                           uint64_t      msg_id,
                           const char    ctx[gimli_secretbox_CONTEXTBYTES],
                           const uint8_t key[gimli_secretbox_KEYBYTES],
                           const uint8_t iv[gimli_secretbox_IVBYTES]);

/* ---------------- */

#define randombytes_SEEDBYTES 32

void randombytes_buf_deterministic(void *out, size_t out_len,
                                   const uint8_t seed[randombytes_SEEDBYTES]);

#ifdef __cplusplus
}
#endif

#endif
