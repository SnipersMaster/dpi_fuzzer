/*
 * fuzz_nsh_parser.c
 *
 * libFuzzer harness for dpi_nsh_parser.c. Targets
 * nsh_dissect_ethertype_payload() directly — NSH is detected via a
 * real EtherType (0x894F) inside dispatch_by_ethertype(), not the
 * normal registry. The TTL field's split-across-two-bytes bit
 * arithmetic is exactly the kind of packed-bitfield logic most
 * likely to hide a subtle bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_nsh_parser fuzz_nsh_parser.c
 * Run:   ./fuzz_nsh_parser fuzz_seeds/nsh/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_nsh_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 64) return 0;

    nsh_dissect_ethertype_payload(Data, (uint16_t)Size);

    return 0;
}
