#ifndef gimli_p_H
#define gimli_p_H

#include <stdint.h>
#include <stddef.h>

#include "common.h"
#include "../gimli.h"

#define gimli_BLOCKBYTES 48
#define gimli_RATE 16

void gimli_core_u8(uint8_t state_u8[gimli_BLOCKBYTES]);

#endif
