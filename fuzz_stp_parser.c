/*
 * fuzz_stp_parser.c
 *
 * libFuzzer harness for dpi_stp_parser.c. Targets
 * stp_dissect_llc_payload() directly rather than going through
 * dispatch_dissection() — STP isn't reached via the normal port/
 * content-based registry the way most dissectors are; it's detected
 * via 802.3 LLC framing inside dispatch_by_ethertype() itself (see
 * that function's own comment in dpi_secure_bootstrap.c). The
 * length-bounded parsing (BPDU content vs. real Ethernet padding,
 * confirmed as a genuine distinction against a real capture — see
 * dpi_stp_parser.c's own header comment) is exactly the kind of
 * length-vs-buffer-size mismatch most likely to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_stp_parser fuzz_stp_parser.c
 * Run:   ./fuzz_stp_parser fuzz_seeds/stp/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_stp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    /* declared_length is fuzzed too, independently of Size, since the
     * real bug class this guards against is exactly a mismatch
     * between the two (a declared length that doesn't match what's
     * actually in the buffer) — first byte doubles as a synthetic
     * declared_length input rather than adding a second fuzzer entry
     * point. */
    uint16_t declared_length = (uint16_t)(Data[0] | ((Size > 1 ? Data[1] : 0) << 8));
    stp_dissect_llc_payload(Data, (uint16_t)Size, declared_length);

    return 0;
}
