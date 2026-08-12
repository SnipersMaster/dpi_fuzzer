/*
 * fuzz_teredo_parser.c
 *
 * libFuzzer harness for dpi_teredo_parser.c. The Authentication
 * header's variable-length ID/AU fields (used to compute the nonce's
 * offset) are exactly the kind of indirect-offset arithmetic most
 * likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_teredo_parser fuzz_teredo_parser.c
 * Run:   ./fuzz_teredo_parser fuzz_seeds/teredo/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_teredo_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    double confidence = teredo_detect(Data, (uint16_t)Size, 3544, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    teredo_dissect(Data, (uint16_t)Size, 3544, "UDP", &out);

    return 0;
}
