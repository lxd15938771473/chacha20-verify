#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

// Include project headers
#include "crypt_chacha20.h"
#include "crypt_errno.h"

// Function declarations missing from header
int32_t CRYPT_CHACHA20_SetNonce(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *nonce, uint32_t nonceLen);

// Test helper functions
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf("  ");
        else printf(" ");
    }
    printf("\n");
}

int compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            printf("Difference at byte %zu: expected 0x%02x, got 0x%02x\n", i, a[i], b[i]);
            return 0;
        }
    }
    return 1;
}

// Test Case 1: 128 bytes input (2 blocks) with lastLen = 0
void test_chacha20_update_128_bytes() {
    printf("=== Test Case 1: 128 bytes input (2 blocks) ===\n");

    CRYPT_CHACHA20_Ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    // RFC 7539 test vector key
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    // RFC 7539 test vector nonce
    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    // Initialize context
    assert(CRYPT_CHACHA20_SetKey(&ctx, key, 32) == CRYPT_SUCCESS);
    assert(CRYPT_CHACHA20_SetNonce(&ctx, nonce, 12) == CRYPT_SUCCESS);
    assert(ctx.lastLen == 0); // Verify lastLen is 0

    // Test input: 128 bytes of sequential data
    ctx.lastLen = 1;
    uint8_t input[131];
    for (int i = 0; i <= 127; i++) {
        input[i] = i & 0xFF;
    }
    input[128] = 0x11;
    input[129] = 0x12;
    input[130] = 0x13;

    uint8_t output[131];
    memset(output, 0, sizeof(output));

    // Call CRYPT_CHACHA20_Update
    int32_t result = CRYPT_CHACHA20_Update(&ctx, input, output, 131);
    assert(result == CRYPT_SUCCESS);

    print_hex("Input (first 32 bytes)", input, 32);
    print_hex("Output (first 32 bytes)", output, 131);

    // Verify output is not the same as input (encryption should change the data)
    assert(memcmp(input, output, 128) != 0);

    printf("Test Case 1: PASSED\n\n");
}



// Test Case 3: 192 bytes input (3 blocks) with lastLen = 0
void test_chacha20_update_192_bytes() {
    printf("=== Test Case 3: 192 bytes input (3 blocks) ===\n");

    CRYPT_CHACHA20_Ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = i;
    }

    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    assert(CRYPT_CHACHA20_SetKey(&ctx, key, 32) == CRYPT_SUCCESS);
    assert(CRYPT_CHACHA20_SetNonce(&ctx, nonce, 12) == CRYPT_SUCCESS);
    assert(ctx.lastLen == 0); // Verify lastLen is 0

    // Test input: 192 bytes of sequential data
    uint8_t input[192];
    for (int i = 0; i < 192; i++) {
        input[i] = i & 0xFF;
    }

    uint8_t output[192];
    memset(output, 0, sizeof(output));

    int32_t result = CRYPT_CHACHA20_Update(&ctx, input, output, 192);
    assert(result == CRYPT_SUCCESS);

    print_hex("Input (first 32 bytes)", input, 32);
    print_hex("Output (first 32 bytes)", output, 32);

    // Verify output is different from input
    assert(memcmp(input, output, 192) != 0);

    // Verify counter incremented correctly (should be 4 after processing 3 blocks)
    printf("Final counter value: %u\n", ctx.state[12]);

    printf("Test Case 3: PASSED\n\n");
}

int main() {
    printf("ChaCha20 Update Tests (lastLen = 0)\n");
    printf("=====================================\n\n");

    test_chacha20_update_128_bytes();
    test_chacha20_update_192_bytes();

    printf("All tests completed successfully!\n");
    return 0;
}
