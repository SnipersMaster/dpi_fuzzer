/*
 * fuzz_smtp_parser.c
 *
 * libFuzzer harness for dpi_smtp_parser.c. Plaintext, no crypto
 * boundary.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_smtp_parser fuzz_smtp_parser.c
 * Run:   ./fuzz_smtp_parser fuzz_seeds/smtp/ -max_len=2048
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_smtp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 2048) return 0;

    double confidence = smtp_detect(Data, (uint16_t)Size, 25, "TCP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    smtp_dissect(Data, (uint16_t)Size, 25, "TCP", &out);

    return 0;
}
