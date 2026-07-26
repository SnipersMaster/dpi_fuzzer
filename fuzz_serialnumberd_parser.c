/*
 * fuzz_serialnumberd_parser.c
 *
 * libFuzzer harness for dpi_serialnumberd_parser.c. The colon-
 * delimited field walk is exactly the kind of variable-length text
 * parsing most likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_serialnumberd_parser fuzz_serialnumberd_parser.c
 * Run:   ./fuzz_serialnumberd_parser fuzz_seeds/serialnumberd/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_serialnumberd_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    double confidence = serialnumberd_detect(Data, (uint16_t)Size, 626, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    serialnumberd_dissect(Data, (uint16_t)Size, 626, "UDP", &out);

    return 0;
}
