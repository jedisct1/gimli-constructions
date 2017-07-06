#include "gimli_p.h"

#define gimli_secretbox_SIVBYTES 20
#define gimli_secretbox_MACBYTES 16

/*
   * First pass:
   pad((str_enc("sbx256") ^ 0x80) || str_enc(context)) || pad(k) ||
   pad(str_enc(iv) || right_enc(msg_id)) || msg

   Output is the nonce.

   * Second pass:
   pad(str_enc("sbx256") || str_enc(context)) || pad(k) ||
   pad(str_enc(nonce) || right_enc(msg_id)) || msg

   This is used to encrypt the message. Output format is: nonce || mac || ciphertext
*/

static void
gimli_secretbox_setup(uint8_t buf[gimli_BLOCKBYTES],
                      uint64_t      msg_id,
                      const char    ctx[gimli_secretbox_CONTEXTBYTES],
                      const uint8_t key[gimli_secretbox_KEYBYTES],
                      const uint8_t iv[gimli_secretbox_IVBYTES],
                      int           first_pass)
{
    static const uint8_t prefix[] = { 6, 's', 'b', 'x', '2', '5', '6', 8 };
    uint8_t msg_id_le[8];

    mem_zero(buf + sizeof prefix + gimli_secretbox_CONTEXTBYTES,
             gimli_BLOCKBYTES - sizeof prefix - gimli_secretbox_CONTEXTBYTES);
    COMPILER_ASSERT(gimli_secretbox_CONTEXTBYTES == 8);
    COMPILER_ASSERT(sizeof prefix + gimli_secretbox_CONTEXTBYTES <= gimli_RATE);
    mem_cpy(buf, prefix, sizeof prefix);
    mem_cpy(buf + sizeof prefix, ctx, gimli_secretbox_CONTEXTBYTES);
    if (first_pass != 0) {
        buf[gimli_RATE - 1] ^= 0x80;
    }
    COMPILER_ASSERT(sizeof prefix + gimli_secretbox_CONTEXTBYTES == gimli_RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(gimli_secretbox_KEYBYTES == 2 * gimli_RATE);
    mem_xor(buf, key, gimli_RATE);
    gimli_core_u8(buf);
    mem_xor(buf, key + gimli_RATE, gimli_RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(gimli_secretbox_IVBYTES < gimli_RATE * 2);
    buf[0] ^= gimli_secretbox_IVBYTES;
    mem_xor(&buf[1], iv, gimli_RATE - 1);
    gimli_core_u8(buf);
    mem_xor(buf, iv + gimli_RATE - 1, gimli_secretbox_IVBYTES - (gimli_RATE - 1));
    STORE64_LE(msg_id_le, msg_id);
    COMPILER_ASSERT(gimli_secretbox_IVBYTES - gimli_RATE + 8 <= gimli_RATE);
    mem_xor(buf + gimli_secretbox_IVBYTES - gimli_RATE, msg_id_le, 8);
    gimli_core_u8(buf);
}


static void
gimli_secretbox_xor(uint8_t buf[gimli_BLOCKBYTES],
                    uint8_t *out, const uint8_t *in, size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, gimli_RATE);
        gimli_core_u8(buf);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, leftover);
        gimli_core_u8(buf);
    }
}

int
gimli_secretbox_encrypt_iv(uint8_t *c, const void *m_, size_t mlen,
                           uint64_t      msg_id,
                           const char    ctx[gimli_secretbox_CONTEXTBYTES],
                           const uint8_t key[gimli_secretbox_KEYBYTES],
                           const uint8_t iv[gimli_secretbox_IVBYTES])
{
    uint32_t       state[gimli_BLOCKBYTES / 4];
    uint8_t       *buf = (uint8_t *) (void *) state;
    const uint8_t *m = (const uint8_t *) m_;
    uint8_t       *siv = &c[0];
    uint8_t       *mac = &c[gimli_secretbox_SIVBYTES];
    uint8_t       *ct = &c[gimli_secretbox_SIVBYTES + gimli_secretbox_MACBYTES];
    size_t         i;
    size_t         leftover;

    /* first pass: compute the siv */

    gimli_secretbox_setup(buf, msg_id, ctx, key, iv, 1);
    for (i = 0; i < mlen / gimli_RATE; i++) {
        mem_xor(buf, &m[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf);
    }
    leftover = mlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor(buf, &m[i * gimli_RATE], leftover);
        gimli_core_u8(buf);
    }
    buf[leftover] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    gimli_core_u8(buf);

    COMPILER_ASSERT(gimli_secretbox_SIVBYTES <= gimli_RATE * 2);
    mem_cpy(siv, buf, gimli_secretbox_SIVBYTES);
    gimli_core_u8(buf);
    mem_cpy(siv + gimli_RATE, buf, gimli_secretbox_SIVBYTES - gimli_RATE);

    /* second pass: encrypt the message, squeeze an extra block for the MAC */

    COMPILER_ASSERT(gimli_secretbox_SIVBYTES == gimli_secretbox_IVBYTES);
    gimli_secretbox_setup(buf, msg_id, ctx, key, siv, 0);

    buf[0] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    gimli_core_u8(buf);

    gimli_secretbox_xor(buf, ct, m, mlen);
    COMPILER_ASSERT(gimli_secretbox_MACBYTES <= gimli_RATE);
    mem_cpy(mac, buf, gimli_secretbox_MACBYTES);

    return 0;
}

int
gimli_secretbox_decrypt(void *m_, const uint8_t *c, size_t clen,
                        uint64_t      msg_id,
                        const char    ctx[gimli_secretbox_CONTEXTBYTES],
                        const uint8_t key[gimli_secretbox_KEYBYTES])
{
    uint32_t       pub_mac[gimli_secretbox_MACBYTES / 4];
    uint32_t       state[gimli_BLOCKBYTES / 4];
    uint8_t       *buf = (uint8_t *) (void *) state;
    const uint8_t *siv = &c[0];
    const uint8_t *mac = &c[gimli_secretbox_SIVBYTES];
    const uint8_t *ct = &c[gimli_secretbox_SIVBYTES + gimli_secretbox_MACBYTES];
    uint8_t       *m = (uint8_t *) m_;
    size_t         mlen;
    uint32_t       cv;

    if (clen < gimli_secretbox_HEADERBYTES) {
        return -1;
    }
    mlen = clen - gimli_secretbox_HEADERBYTES;
    mem_cpy(pub_mac, mac, sizeof pub_mac);
    COMPILER_ASSERT(gimli_secretbox_SIVBYTES == gimli_secretbox_IVBYTES);
    gimli_secretbox_setup(buf, msg_id, ctx, key, siv, 0);
    buf[0] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    gimli_core_u8(buf);

    gimli_secretbox_xor(buf, m, ct, mlen);
    COMPILER_ASSERT(gimli_secretbox_MACBYTES <= gimli_RATE);
    cv = mem_ct_cmp_u32(state, pub_mac, gimli_secretbox_MACBYTES / 4);
    mem_ct_zero_u32(state, gimli_BLOCKBYTES / 4);
    if (cv != 0) {
        mem_zero(m, mlen);
        return -1;
    }
    return 0;
}
