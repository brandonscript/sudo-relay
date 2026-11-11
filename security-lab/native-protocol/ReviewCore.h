#include <stddef.h>
#include <stdint.h>

// Returns byte count, -1 invalid input, -2 insufficient capacity; errors write nothing.
// Caller owns all buffers. Authenticate the request source before calling.
intptr_t sudo_relay_prepare_review(const uint8_t *input, size_t input_len,
    const uint8_t *machine, size_t machine_len, uint64_t now,
    uint8_t *output, size_t capacity);
