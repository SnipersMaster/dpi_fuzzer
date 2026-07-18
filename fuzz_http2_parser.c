/*
 * fuzz_http2_parser.c
 *
 * libFuzzer harness for dpi_http2_parser.c — frame-level parsing only
 * (HPACK is explicitly out of scope, see that file's header comment).
 * Plaintext frame headers, no crypto boundary.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_http2_parser fuzz_http2_parser.c
 * Run:   ./fuzz_http2_parser fuzz_seeds/http2/ -max_len=4096
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_http2_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 4096) return 0;

    double confidence = http2_detect(Data, (uint16_t)Size, 443, "TCP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    http2_dissect(Data, (uint16_t)Size, 443, "TCP", &out);

    return 0;
}
