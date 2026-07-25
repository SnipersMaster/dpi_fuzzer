/*
 * fuzz_appletalk_parser.c
 *
 * libFuzzer harness for dpi_appletalk_parser.c. Targets
 * appletalk_dissect_snap_payload() directly — AppleTalk is detected
 * via SNAP/OUI framing inside dispatch_by_ethertype(), not the
 * normal port/content-based registry, the same reasoning as
 * fuzz_stp_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_appletalk_parser fuzz_appletalk_parser.c
 * Run:   ./fuzz_appletalk_parser fuzz_seeds/appletalk/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_appletalk_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    appletalk_dissect_snap_payload(Data, (uint16_t)Size);

    return 0;
}
