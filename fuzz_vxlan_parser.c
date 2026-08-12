/*
 * fuzz_vxlan_parser.c
 *
 * libFuzzer harness for dpi_vxlan_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_vxlan_parser fuzz_vxlan_parser.c
 * Run:   ./fuzz_vxlan_parser fuzz_seeds/vxlan/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_vxlan_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 64) return 0;

    double confidence = vxlan_detect(Data, (uint16_t)Size, 4789, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    vxlan_dissect(Data, (uint16_t)Size, 4789, "UDP", &out);

    return 0;
}
