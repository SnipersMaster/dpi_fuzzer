/*
 * fuzz_sip_rtp_parser.c
 *
 * libFuzzer harness for dpi_sip_rtp_parser.c — both SIP (text-based)
 * and RTP (fixed binary header) from the same fuzz input, picking
 * which to exercise based on an input byte. Plaintext, no crypto
 * boundary for either.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_sip_rtp_parser fuzz_sip_rtp_parser.c
 * Run:   ./fuzz_sip_rtp_parser fuzz_seeds/sip_rtp/ -max_len=2048
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_sip_rtp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 2048) return 0;

    double sip_conf = sip_detect(Data, (uint16_t)Size, 5060, "UDP");
    if (sip_conf > 0.3) {
        struct dissect_result out;
        sip_dissect(Data, (uint16_t)Size, 5060, "UDP", &out);
    }

    double rtp_conf = rtp_detect(Data, (uint16_t)Size, 0, "UDP");
    if (rtp_conf > 0.3) {
        struct dissect_result out2;
        rtp_dissect(Data, (uint16_t)Size, 0, "UDP", &out2);
    }

    return 0;
}
