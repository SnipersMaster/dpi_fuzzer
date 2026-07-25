/*
 * fuzz_pim_parser.c
 *
 * libFuzzer harness for dpi_pim_parser.c. The Hello-message option
 * walk is exactly the kind of variable-length-field loop most likely
 * to hide a bounds bug — same reasoning as this project's other
 * TLV-walking harnesses.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_pim_parser fuzz_pim_parser.c
 * Run:   ./fuzz_pim_parser fuzz_seeds/pim/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_pim_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = pim_detect(Data, (uint16_t)Size, 0, "PIM");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    pim_dissect(Data, (uint16_t)Size, 0, "PIM", &out);

    return 0;
}
