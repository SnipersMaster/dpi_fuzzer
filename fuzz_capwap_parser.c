/*
 * fuzz_capwap_parser.c
 *
 * libFuzzer harness for dpi_capwap_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_capwap_parser fuzz_capwap_parser.c
 * Run:   ./fuzz_capwap_parser fuzz_seeds/capwap/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_capwap_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 64) return 0;

    double confidence = capwap_detect(Data, (uint16_t)Size, 5246, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    capwap_dissect(Data, (uint16_t)Size, 5246, "UDP", &out);

    return 0;
}
