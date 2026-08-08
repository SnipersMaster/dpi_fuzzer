/*
 * fuzz_openvpn_parser.c
 *
 * libFuzzer harness for dpi_openvpn_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_openvpn_parser fuzz_openvpn_parser.c
 * Run:   ./fuzz_openvpn_parser fuzz_seeds/openvpn/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_openvpn_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = openvpn_detect(Data, (uint16_t)Size, 1194, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    openvpn_dissect(Data, (uint16_t)Size, 1194, "UDP", &out);

    return 0;
}
