/*
 * fuzz_tftp_parser.c
 *
 * libFuzzer harness for dpi_tftp_parser.c, covering RRQ/WRQ (real-
 * traffic-verified) and DATA/ACK/ERROR (implemented from spec, see
 * the dissector's own header comment).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_tftp_parser fuzz_tftp_parser.c
 * Run:   ./fuzz_tftp_parser fuzz_seeds/tftp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_tftp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = tftp_detect(Data, (uint16_t)Size, 69, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    tftp_dissect(Data, (uint16_t)Size, 69, "UDP", &out);

    return 0;
}
