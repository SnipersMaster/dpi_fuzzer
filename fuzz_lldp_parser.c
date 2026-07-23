/*
 * fuzz_lldp_parser.c
 *
 * libFuzzer harness for dpi_lldp_parser.c. Plaintext TLV walking, no
 * crypto boundary, no capture-path dependency chain needed.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_lldp_parser fuzz_lldp_parser.c
 * Run:   ./fuzz_lldp_parser fuzz_seeds/lldp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_lldp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = lldp_detect(Data, (uint16_t)Size, 0, "");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    lldp_dissect(Data, (uint16_t)Size, 0, "", &out);

    return 0;
}
