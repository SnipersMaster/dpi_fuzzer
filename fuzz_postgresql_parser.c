/*
 * fuzz_postgresql_parser.c
 *
 * libFuzzer harness for dpi_postgresql_parser.c. The parameter-string
 * walk (alternating NUL-terminated name/value pairs) is exactly the
 * kind of variable-length loop most likely to hide a bounds bug if
 * the terminator search runs past the buffer.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_postgresql_parser fuzz_postgresql_parser.c
 * Run:   ./fuzz_postgresql_parser fuzz_seeds/postgresql/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_postgresql_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = postgresql_detect(Data, (uint16_t)Size, 5432, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    postgresql_dissect(Data, (uint16_t)Size, 5432, "TCP", &out);

    return 0;
}
