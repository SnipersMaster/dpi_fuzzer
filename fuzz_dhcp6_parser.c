/*
 * fuzz_dhcp6_parser.c
 *
 * libFuzzer harness for dpi_dhcp6_parser.c. The options TLV walk is
 * exactly the kind of variable-length loop most likely to hide a
 * bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_dhcp6_parser fuzz_dhcp6_parser.c
 * Run:   ./fuzz_dhcp6_parser fuzz_seeds/dhcp6/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_dhcp6_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = dhcp6_detect(Data, (uint16_t)Size, 547, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    dhcp6_dissect(Data, (uint16_t)Size, 547, "UDP", &out);

    return 0;
}
