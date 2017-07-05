#include "gimli_p.h"

int
gimli_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len,
                          uint64_t      subkey_id,
                          const char    ctx[gimli_kdf_CONTEXTBYTES],
                          const uint8_t key[gimli_kdf_KEYBYTES])
{
    gimli_hash_state st;

    COMPILER_ASSERT(gimli_kdf_CONTEXTBYTES == gimli_hash_CONTEXTBYTES);
    if (gimli_hash_init_with_tweak(&st, ctx, subkey_id, key,
                                   gimli_kdf_KEYBYTES) != 0) {
        return -1;
    }
    return gimli_hash_final(&st, subkey, subkey_len);
}
