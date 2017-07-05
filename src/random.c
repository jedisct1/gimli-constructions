#include "gimli_p.h"

/* pad(str_enc("drbg256")) || pad(seed) */

void
randombytes_buf_deterministic(void *out, size_t out_len,
                              const uint8_t seed[randombytes_SEEDBYTES])
{
    static const uint8_t prefix[] = { 7, 'd', 'r', 'b', 'g', '2', '5', '6' };
    uint8_t buf[BLOCK_SIZE];
    int     i;

    COMPILER_ASSERT(sizeof prefix <= RATE);
    mem_cpy(buf, prefix, sizeof prefix);
    mem_zero(buf + sizeof prefix, sizeof buf - sizeof prefix);
    gimli_core_u8(buf);

    COMPILER_ASSERT(randombytes_SEEDBYTES == 2 * RATE);
    mem_xor(buf, seed, RATE);
    gimli_core_u8(buf);
    mem_xor(buf, seed + RATE, RATE);
    gimli_core_u8(buf);

    buf[0] ^= 0x1f;
    buf[RATE - 1] ^= 0x80;
    for (i = 0; out_len > 0; i++) {
        const size_t block_size = (out_len < BLOCK_SIZE) ? out_len : BLOCK_SIZE;
        gimli_core_u8(buf);
        mem_cpy((uint8_t *) out + i * BLOCK_SIZE, buf, block_size);
        out_len -= block_size;
    }
}
