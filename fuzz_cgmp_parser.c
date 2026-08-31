/*
 * fuzz_cgmp_parser.c
 *
 * libFuzzer harness for dpi_cgmp_parser.c. Targets
 * cgmp_dissect_snap_payload() directly — CGMP is detected via SNAP/
 * OUI+PID framing inside dispatch_by_ethertype(), not the normal
 * registry.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_cgmp_parser fuzz_cgmp_parser.c
 * Run:   ./fuzz_cgmp_parser fuzz_seeds/cgmp/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_cgmp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 64) return 0;

    cgmp_dissect_snap_payload(Data, (uint16_t)Size);

    return 0;
}
