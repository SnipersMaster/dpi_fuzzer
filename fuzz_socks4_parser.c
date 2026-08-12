/*
 * fuzz_socks4_parser.c
 *
 * libFuzzer harness for dpi_socks4_parser.c. The NUL-terminated
 * USERID and SOCKS4a hostname fields are exactly the kind of
 * variable-length text scanning most likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_socks4_parser fuzz_socks4_parser.c
 * Run:   ./fuzz_socks4_parser fuzz_seeds/socks4/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_socks4_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = socks4_detect(Data, (uint16_t)Size, 1080, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    socks4_dissect(Data, (uint16_t)Size, 1080, "TCP", &out);

    return 0;
}
