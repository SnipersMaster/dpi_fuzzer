/*
 * fuzz_isl_parser.c
 *
 * libFuzzer harness for dpi_isl_parser.c. Targets
 * isl_dissect_raw_frame() directly — ISL is detected on the raw
 * frame buffer before any standard Ethernet-header extraction
 * (called from parse_ethernet_frame()'s very first lines / dissect_
 * packet()'s equivalent in the DPDK worker), not through the normal
 * dispatch_by_ethertype() chain or registry.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_isl_parser fuzz_isl_parser.c
 * Run:   ./fuzz_isl_parser fuzz_seeds/isl/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_isl_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    isl_dissect_raw_frame(Data, (ssize_t)Size);

    return 0;
}
