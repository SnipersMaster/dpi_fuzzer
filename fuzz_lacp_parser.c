/*
 * fuzz_lacp_parser.c
 *
 * libFuzzer harness for dpi_lacp_parser.c. Targets
 * lacp_dissect_ethertype_payload() directly — LACP is detected via a
 * real EtherType (0x8809) inside dispatch_by_ethertype(), not the
 * normal registry. The TLV walk (and the Actor/Partner Information
 * TLV's offset math specifically, where a real bug was caught during
 * this dissector's own verification) is exactly the kind of
 * variable-length-field logic most likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_lacp_parser fuzz_lacp_parser.c
 * Run:   ./fuzz_lacp_parser fuzz_seeds/lacp/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_lacp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    lacp_dissect_ethertype_payload(Data, (uint16_t)Size);

    return 0;
}
