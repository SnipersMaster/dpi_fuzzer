/*
 * fuzz_ipxsap_parser.c
 *
 * libFuzzer harness for dpi_ipxsap_parser.c. Targets ipxsap_dissect()
 * directly. The Server Name field's NUL-scan (bounded to 48 bytes)
 * and the fixed-stride entry walk are exactly the kind of variable-
 * length parsing most likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_ipxsap_parser fuzz_ipxsap_parser.c
 * Run:   ./fuzz_ipxsap_parser fuzz_seeds/ipxsap/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_ipxsap_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    ipxsap_dissect(Data, (uint16_t)Size);

    return 0;
}
