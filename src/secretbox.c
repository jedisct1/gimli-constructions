#include "gimli_p.h"

#define SIVBYTES 20
#define MACBYTES 16

/*
   * First pass:
   pad(str_enc("sbx256") || str_enc(context)) || pad(k) ||
   pad(str_enc(iv) || right_enc(msg_id)) || msg

   Output is the nonce.

   * Second pass:
   pad(str_enc("sbx256") || str_enc(context)) || pad(k) ||
   pad(str_enc(nonce) || right_enc(msg_id)) || msg

   This is used to encrypt the message. Output format is: nonce || mac || ciphertext
*/

int
gimli_secretbox_encrypt_iv(uint8_t *c, const void *m_, size_t mlen,
                           uint64_t      msg_id,
                           const char    ctx[gimli_secretbox_CONTEXTBYTES],
                           const uint8_t key[gimli_secretbox_KEYBYTES],
                           const uint8_t iv[gimli_secretbox_IVBYTES])
{
    static const uint8_t prefix[] = { 6, 's', 'b', 'x', '2', '5', '6', 8 };
    uint8_t        buf[BLOCK_SIZE];
    const uint8_t *m = (const uint8_t *) m_;
    uint8_t       *siv = &c[0];
    uint8_t       *mac = &c[SIVBYTES];
    uint8_t       *ct = &c[SIVBYTES + MACBYTES];
    uint8_t        msg_id_le[8];
    size_t         i;
    size_t         leftover;

    /* first pass: compute the siv */

    mem_zero(buf, sizeof buf);
    COMPILER_ASSERT(gimli_secretbox_CONTEXTBYTES == 8);
    COMPILER_ASSERT(sizeof prefix + gimli_secretbox_CONTEXTBYTES <= RATE);
    mem_cpy(buf, prefix, sizeof prefix);
    mem_cpy(buf + sizeof prefix, ctx, gimli_secretbox_CONTEXTBYTES);
    buf[RATE - 1] ^= 0x80; /* only for the first pass */
    COMPILER_ASSERT(sizeof prefix + gimli_secretbox_CONTEXTBYTES == RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(gimli_secretbox_KEYBYTES == 2 * RATE);
    mem_xor(buf, key, RATE);
    gimli_core_u8(buf);
    mem_xor(buf, key + RATE, RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(gimli_secretbox_IVBYTES < RATE * 2);
    buf[0] ^= gimli_secretbox_IVBYTES;
    mem_xor(&buf[1], iv, RATE - 1);
    gimli_core_u8(buf);
    mem_xor(buf, iv + RATE - 1, gimli_secretbox_IVBYTES - (RATE - 1));
    STORE64_LE(msg_id_le, msg_id);
    COMPILER_ASSERT(gimli_secretbox_IVBYTES - RATE + 8 <= RATE);
    mem_xor(buf + gimli_secretbox_IVBYTES - RATE, msg_id_le, 8);
    gimli_core_u8(buf);

    for (i = 0; i < mlen / RATE; i++) {
        mem_xor(buf, &m[i * RATE], RATE);
        gimli_core_u8(buf);
    }
    leftover = mlen % RATE;
    mem_xor(buf, &m[i * RATE], leftover);
    gimli_core_u8(buf);

    buf[leftover] ^= 0x1f;
    buf[RATE - 1] ^= 0x80;

    gimli_core_u8(buf);
    COMPILER_ASSERT(SIVBYTES <= RATE * 2);
    mem_cpy(siv, buf, SIVBYTES);
    gimli_core_u8(buf);
    mem_cpy(siv + RATE, buf, SIVBYTES - RATE);

    /* second pass: encrypt the message, squeeze an extra block for the MAC */

    mem_zero(buf, sizeof buf);
    mem_cpy(buf, prefix, sizeof prefix);
    mem_cpy(buf + sizeof prefix, ctx, gimli_secretbox_CONTEXTBYTES);
    COMPILER_ASSERT(sizeof prefix + gimli_secretbox_CONTEXTBYTES == RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(gimli_secretbox_KEYBYTES == 2 * RATE);
    mem_xor(buf, key, RATE);
    gimli_core_u8(buf);
    mem_xor(buf, key + RATE, RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(SIVBYTES < RATE * 2);
    buf[0] ^= SIVBYTES;
    mem_xor(&buf[1], siv, RATE - 1);
    gimli_core_u8(buf);
    mem_xor(buf, siv + RATE - 1, SIVBYTES - (RATE - 1));
    STORE64_LE(msg_id_le, msg_id);
    COMPILER_ASSERT(SIVBYTES - RATE + 8 <= RATE);
    mem_xor(buf + SIVBYTES - RATE, msg_id_le, 8);
    gimli_core_u8(buf);

    buf[leftover] ^= 0x1f;
    buf[RATE - 1] ^= 0x80;

    gimli_core_u8(buf);

    for (i = 0; i < mlen / RATE; i++) {
        mem_xor2(&ct[i * RATE], &m[i * RATE], buf, RATE);
        gimli_core_u8(buf);
    }
    leftover = mlen % RATE;
    mem_xor2(&ct[i * RATE], &m[i * RATE], buf, leftover);

    gimli_core_u8(buf);
    COMPILER_ASSERT(MACBYTES <= RATE);
    mem_cpy(mac, buf, MACBYTES);

    return 0;
}
