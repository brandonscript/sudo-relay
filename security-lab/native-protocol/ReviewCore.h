#include <stddef.h>
#include <stdint.h>

// Root-controlled regular file, at most 4096 bytes; errors leave output unchanged.
// Returns byte count, -1 invalid/unprotected input, -2 insufficient capacity.
intptr_t sudo_relay_read_peer_policy(const uint8_t *path, size_t path_len,
    uint8_t *output, size_t capacity);

// JSON {socket,id,machine_id}, <=4096 bytes; socket and machine pin require trusted enrollment.
// Fetch only: authenticates root peer and validates frozen request. Never submits approval.
// Returns pending JSON byte count, -1 failure, -2 insufficient capacity; errors write nothing.
intptr_t sudo_relay_fetch_review(const uint8_t *input, size_t input_len,
    uint8_t *output, size_t capacity);

// Returns byte count, -1 invalid input, -2 insufficient capacity; errors write nothing.
// Caller owns all buffers. Authenticate the request source before calling.
intptr_t sudo_relay_prepare_review(const uint8_t *input, size_t input_len,
    const uint8_t *machine, size_t machine_len, uint64_t now,
    uint8_t *output, size_t capacity);
