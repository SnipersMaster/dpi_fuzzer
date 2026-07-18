/*
 * fuzz_dhcp_parser.c
 *
 * libFuzzer harness for dpi_dhcp_parser.c. Plaintext TLV options,
 * no crypto boundary.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_dhcp_parser fuzz_dhcp_parser.c
 * Run:   ./fuzz_dhcp_parser fuzz_seeds/dhcp/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_dhcp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    double confidence = dhcp_detect(Data, (uint16_t)Size, 67, "UDP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    dhcp_dissect(Data, (uint16_t)Size, 67, "UDP", &out);

    return 0;
}
