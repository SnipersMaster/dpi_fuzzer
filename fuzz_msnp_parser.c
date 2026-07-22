/*
 * fuzz_msnp_parser.c
 *
 * libFuzzer harness for dpi_msnp_parser.c. Plaintext, no crypto
 * boundary, no capture-path dependency chain needed.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_msnp_parser fuzz_msnp_parser.c
 * Run:   ./fuzz_msnp_parser fuzz_seeds/msnp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_msnp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = msnp_detect(Data, (uint16_t)Size, 1863, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    msnp_dissect(Data, (uint16_t)Size, 1863, "TCP", &out);

    return 0;
}
