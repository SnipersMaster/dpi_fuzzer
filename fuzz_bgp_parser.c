/*
 * fuzz_bgp_parser.c
 *
 * libFuzzer harness for dpi_bgp_parser.c, including its multi-message-
 * per-buffer walk (confirmed necessary against real traffic — see the
 * file's own header comment for why).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_bgp_parser fuzz_bgp_parser.c
 * Run:   ./fuzz_bgp_parser fuzz_seeds/bgp/ -max_len=2048
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_bgp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 2048) return 0;

    double confidence = bgp_detect(Data, (uint16_t)Size, 179, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    bgp_dissect(Data, (uint16_t)Size, 179, "TCP", &out);

    return 0;
}
