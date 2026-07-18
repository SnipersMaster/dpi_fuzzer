/*
 * fuzz_radius_parser.c
 *
 * libFuzzer harness for dpi_radius_parser.c. RADIUS's attribute-value
 * pairs are plaintext (RFC 2865 §5) — no crypto boundary to split
 * around, unlike the QUIC harnesses. Raw-byte fuzzing is the direct
 * and correct approach here, same as the RFC parser harness.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_radius_parser fuzz_radius_parser.c
 * Run:   ./fuzz_radius_parser fuzz_seeds/radius/ -max_len=4096
 *
 * NOT RUN in this environment — reviewed but not executed.
 */

#include <stdint.h>
#include <stddef.h>

/* Skip register_all_dissectors() — this harness only needs RADIUS,
 * not the full multi-protocol dependency graph (which would otherwise
 * pull in QUIC/OpenSSL, GTP, and DNS just to satisfy an unused
 * function's extern references). See the guard's explanation in
 * dpi_dissector_registry.c. */
#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_radius_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 4096) return 0;

    /* Fuzz both standard RADIUS ports across runs by using the first
     * byte to pick, rather than fixing one — cheap way to get a bit
     * more coverage variety without a second harness. */
    uint16_t port = (Data[0] & 0x01) ? 1812 : 1813;

    double confidence = radius_detect(Data, (uint16_t)Size, port, "UDP");
    if (confidence <= 0.3) return 0;   /* mirrors dispatch_dissection()'s threshold */

    struct dissect_result out;
    radius_dissect(Data, (uint16_t)Size, port, "UDP", &out);

    return 0;
}
