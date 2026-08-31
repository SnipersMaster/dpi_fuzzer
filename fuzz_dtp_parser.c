/*
 * fuzz_dtp_parser.c
 *
 * libFuzzer harness for dpi_dtp_parser.c. Targets
 * dtp_dissect_snap_payload() directly — DTP is detected via SNAP/
 * OUI+PID framing inside dispatch_by_ethertype(), not the normal
 * registry. The TLV walk is exactly the kind of variable-length-
 * field loop most likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_dtp_parser fuzz_dtp_parser.c
 * Run:   ./fuzz_dtp_parser fuzz_seeds/dtp/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_dtp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    dtp_dissect_snap_payload(Data, (uint16_t)Size);

    return 0;
}
