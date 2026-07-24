/*
 * fuzz_wow_parser.c
 *
 * libFuzzer harness for dpi_wow_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_wow_parser fuzz_wow_parser.c
 * Run:   ./fuzz_wow_parser fuzz_seeds/wow/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_wow_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = wow_detect(Data, (uint16_t)Size, 3724, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    wow_dissect(Data, (uint16_t)Size, 3724, "TCP", &out);

    return 0;
}
