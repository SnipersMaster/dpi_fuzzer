/*
 * fuzz_mobileip_parser.c
 *
 * libFuzzer harness for dpi_mobileip_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_mobileip_parser fuzz_mobileip_parser.c
 * Run:   ./fuzz_mobileip_parser fuzz_seeds/mobileip/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_mobileip_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 64) return 0;

    double confidence = mobileip_detect(Data, (uint16_t)Size, 434, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    mobileip_dissect(Data, (uint16_t)Size, 434, "UDP", &out);

    return 0;
}
