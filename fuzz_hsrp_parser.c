/*
 * fuzz_hsrp_parser.c
 *
 * libFuzzer harness for dpi_hsrp_parser.c. Plaintext binary protocol,
 * no crypto boundary, no capture-path dependency chain needed.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_hsrp_parser fuzz_hsrp_parser.c
 * Run:   ./fuzz_hsrp_parser fuzz_seeds/hsrp/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_hsrp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    double confidence = hsrp_detect(Data, (uint16_t)Size, 1985, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    hsrp_dissect(Data, (uint16_t)Size, 1985, "UDP", &out);

    return 0;
}
