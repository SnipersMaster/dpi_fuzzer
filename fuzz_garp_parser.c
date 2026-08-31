/*
 * fuzz_garp_parser.c
 *
 * libFuzzer harness for dpi_garp_parser.c. Targets
 * garp_dissect_llc_payload() directly — GARP shares STP's own LLC
 * DSAP/SSAP signature (0x42/0x42), not the normal registry. The
 * nested Message/Attribute walk (two levels of variable-length,
 * self-terminating structure) is exactly the kind of parsing most
 * likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_garp_parser fuzz_garp_parser.c
 * Run:   ./fuzz_garp_parser fuzz_seeds/garp/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_garp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    garp_dissect_llc_payload(Data, (uint16_t)Size);

    return 0;
}
