/*
 * fuzz_pptp_parser.c
 *
 * libFuzzer harness for dpi_pptp_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_pptp_parser fuzz_pptp_parser.c
 * Run:   ./fuzz_pptp_parser fuzz_seeds/pptp/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_pptp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    double confidence = pptp_detect(Data, (uint16_t)Size, 1723, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    pptp_dissect(Data, (uint16_t)Size, 1723, "TCP", &out);

    return 0;
}
