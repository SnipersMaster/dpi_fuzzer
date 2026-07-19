/*
 * fuzz_stun_parser.c
 *
 * libFuzzer harness for dpi_stun_parser.c. Plaintext, no crypto
 * boundary. Closes the same "existed, registered, but never fuzzed"
 * gap as fuzz_arp_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_stun_parser fuzz_stun_parser.c
 * Run:   ./fuzz_stun_parser fuzz_seeds/stun/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_stun_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    double confidence = stun_detect(Data, (uint16_t)Size, 3478, "UDP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    stun_dissect(Data, (uint16_t)Size, 3478, "UDP", &out);

    return 0;
}
