
#include "gimli_p.h"

#define BLOCK_SIZE 48
#define RATE 16

int
gimli_hash_update(gimli_hash_state *state, const void *in_, size_t in_len)
{
    const uint8_t *in = (const uint8_t *) in_;
    uint8_t       *buf = (uint8_t *) (void *) state->state;
    size_t         left;
    size_t         ps;
    size_t         i;

    while (in_len > 0) {
        if ((left = RATE - state->buf_off) == 0) {
            gimli_core_u8(buf);
            state->buf_off = 0;
            left = RATE;
        }
        if ((ps = in_len) > left) {
            ps = left;
        }
        for (i = 0; i < ps; i++) {
            buf[state->buf_off + i] ^= in[i];
        }
        state->buf_off += (uint8_t) ps;
        in += ps;
        in_len -= ps;
    }
    return 0;
}

int
gimli_hash_init(gimli_hash_state *state,
                const char ctx[gimli_hash_CONTEXTBYTES],
                const uint8_t *key, size_t key_len)
{
    uint8_t block[64] = { 4, 'k', 'm', 'a', 'c', 8 };
    size_t  p;

    if ((key != NULL && (key_len < gimli_hash_KEYBYTES_MIN ||
                         key_len > gimli_hash_KEYBYTES_MAX)) ||
        (key == NULL && key_len > 0)) {
        return -1;
    }
    COMPILER_ASSERT(gimli_hash_KEYBYTES_MAX <= sizeof block - RATE - 1);
    COMPILER_ASSERT(gimli_hash_CONTEXTBYTES == 8);
    mem_zero(block + 14, sizeof block - 14);
    mem_cpy(block + 6, ctx, 8);
    block[RATE] = (uint8_t) key_len;
    mem_cpy(block + RATE + 1, key, key_len);
    p = (RATE + 1 + key_len + (RATE - 1)) & ~ (size_t) (RATE - 1);
    mem_zero(state, sizeof *state);
    gimli_hash_update(state, block, p);

    return 0;
}

int
gimli_hash_init_with_tweak(gimli_hash_state *state,
                           const char ctx[gimli_hash_CONTEXTBYTES],
                           uint64_t tweak, const uint8_t *key, size_t key_len)
{
    uint8_t block[80] = { 4, 't', 'm', 'a', 'c', 8 };
    size_t  p;

    if ((key != NULL && (key_len < gimli_hash_KEYBYTES_MIN ||
                         key_len > gimli_hash_KEYBYTES_MAX)) ||
        (key == NULL && key_len > 0)) {
        return -1;
    }
    COMPILER_ASSERT(gimli_hash_KEYBYTES_MAX <= sizeof block - 2 * RATE - 1);
    COMPILER_ASSERT(gimli_hash_CONTEXTBYTES == 8);
    mem_zero(block + 14, sizeof block - 14);
    mem_cpy(block + 6, ctx, 8);
    block[RATE] = (uint8_t) key_len;
    mem_cpy(block + RATE + 1, key, key_len);
    p = (RATE + 1 + key_len + (RATE - 1)) & ~ (size_t) (RATE - 1);
    block[p] = (uint8_t) sizeof tweak;
    STORE64_LE(&block[p + 1], tweak);
    p += RATE;
    mem_zero(state, sizeof *state);
    gimli_hash_update(state, block, p);

    return 0;
}

int
gimli_hash_final(gimli_hash_state *state, uint8_t *out, size_t out_len)
{
    uint8_t  lc[4];
    uint8_t *buf = (uint8_t *) (void *) state->state;
    size_t   i;
    size_t   lc_len;

    if (out_len < gimli_hash_BYTES_MIN || out_len > gimli_hash_BYTES_MAX) {
        return -1;
    }
    COMPILER_ASSERT(gimli_hash_BYTES_MAX <= 0xffff);
    lc[1] = (uint8_t) out_len;
    lc[2] = (uint8_t) (out_len >> 8);
    lc[3] = 0;
    lc_len = (size_t) (1 + (lc[2] != 0));
    lc[0] = (uint8_t) lc_len;
    gimli_hash_update(state, lc, 1 + lc_len + 1);

    buf[state->buf_off] ^= 0x1f;
    buf[RATE - 1] ^= 0x80;

    for (i = 0; out_len > 0; i++) {
        const size_t block_size = (out_len < BLOCK_SIZE) ? out_len : BLOCK_SIZE;
        gimli_core_u8(buf);
        mem_cpy(out + i * BLOCK_SIZE, buf, block_size);
        out_len -= block_size;
    }
    return 0;
}
