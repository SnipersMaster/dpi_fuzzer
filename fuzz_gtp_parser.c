/*
 * fuzz_gtp_parser.c
 *
 * libFuzzer harness for dpi_gtp_parser.c (GTP-U v1 + GTPv2-C). Both
 * are plaintext header structures — no crypto boundary, same
 * straightforward raw-byte fuzzing approach as RADIUS/RFC parser.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_gtp_parser fuzz_gtp_parser.c
 * Run:   ./fuzz_gtp_parser fuzz_seeds/gtp/ -max_len=1500
 *
 * NOT RUN in this environment — reviewed but not executed.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_gtp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1500) return 0;

    /* Exercise both GTPv1-U and GTPv2-C from the same input, picking
     * which port/detector to try based on a bit of the input — cheap
     * way to cover both without two separate harnesses. */
    uint16_t port = (Data[0] & 0x01) ? 2152 : 2123;

    double conf1 = gtp1_detect(Data, (uint16_t)Size, port, "UDP");
    if (conf1 > 0.3) {
        struct dissect_result out;
        gtp1_dissect(Data, (uint16_t)Size, port, "UDP", &out);
    }

    double conf2 = gtpv2_detect(Data, (uint16_t)Size, port, "UDP");
    if (conf2 > 0.3) {
        struct dissect_result out2;
        gtpv2_dissect(Data, (uint16_t)Size, port, "UDP", &out2);
    }

    return 0;
}
