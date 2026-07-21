/*
 * fuzz_eigrp_parser.c
 *
 * libFuzzer harness for dpi_eigrp_parser.c. Plaintext binary
 * header+TLV-framing extraction (no TLV value decoding — see the
 * file's own header comment for why), no crypto boundary.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_eigrp_parser fuzz_eigrp_parser.c
 * Run:   ./fuzz_eigrp_parser fuzz_seeds/eigrp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_eigrp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = eigrp_detect(Data, (uint16_t)Size, 0, "");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    eigrp_dissect(Data, (uint16_t)Size, 0, "", &out);

    return 0;
}
