/*
 * fuzz_ntp_parser.c
 *
 * libFuzzer harness for dpi_ntp_parser.c. Plaintext, no crypto
 * boundary. Closes the same "existed, registered, but never fuzzed"
 * gap as fuzz_arp_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_ntp_parser fuzz_ntp_parser.c
 * Run:   ./fuzz_ntp_parser fuzz_seeds/ntp/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_ntp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    double confidence = ntp_detect(Data, (uint16_t)Size, 123, "UDP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    ntp_dissect(Data, (uint16_t)Size, 123, "UDP", &out);

    return 0;
}
