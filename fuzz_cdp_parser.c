/*
 * fuzz_cdp_parser.c
 *
 * libFuzzer harness for dpi_cdp_parser.c. Targets
 * cdp_dissect_snap_payload() directly — CDP is detected via SNAP/OUI
 * framing inside dispatch_by_ethertype(), not the normal registry.
 * The TLV walk is exactly the kind of variable-length-field loop
 * most likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_cdp_parser fuzz_cdp_parser.c
 * Run:   ./fuzz_cdp_parser fuzz_seeds/cdp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_cdp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    cdp_dissect_snap_payload(Data, (uint16_t)Size);

    return 0;
}
