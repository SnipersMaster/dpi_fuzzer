/*
 * fuzz_isakmp_parser.c
 *
 * libFuzzer harness for dpi_isakmp_parser.c. Plaintext binary
 * header-only extraction (no payload parsing), no crypto boundary,
 * no capture-path dependency chain needed.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_isakmp_parser fuzz_isakmp_parser.c
 * Run:   ./fuzz_isakmp_parser fuzz_seeds/isakmp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_isakmp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = isakmp_detect(Data, (uint16_t)Size, 500, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    isakmp_dissect(Data, (uint16_t)Size, 500, "UDP", &out);

    return 0;
}
