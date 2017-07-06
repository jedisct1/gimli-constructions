#ifndef gimli_p_H
#define gimli_p_H

#include <stdint.h>
#include <stddef.h>

#include "common.h"
#include "../gimli.h"

#define BLOCK_SIZE 48
#define RATE 16

void gimli_core_u8(uint8_t state_u8[BLOCK_SIZE]);

#endif
