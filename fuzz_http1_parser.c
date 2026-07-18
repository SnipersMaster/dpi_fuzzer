/*
 * fuzz_http1_parser.c
 *
 * libFuzzer harness for dpi_http1_parser.c. Plaintext, no crypto
 * boundary.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_http1_parser fuzz_http1_parser.c
 * Run:   ./fuzz_http1_parser fuzz_seeds/http1/ -max_len=4096
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_http1_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 4096) return 0;

    double confidence = http1_detect(Data, (uint16_t)Size, 80, "TCP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    http1_dissect(Data, (uint16_t)Size, 80, "TCP", &out);

    return 0;
}
