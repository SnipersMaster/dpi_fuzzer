/*
 * fuzz_pppoe_parser.c
 *
 * libFuzzer harness for dpi_pppoe_parser.c. Targets
 * pppoe_dissect_ethertype_payload() directly — PPPoE is detected via
 * real EtherTypes (0x8863/0x8864) inside dispatch_by_ethertype(), not
 * the normal port/content registry. The Discovery-stage TAG walk is
 * exactly the kind of variable-length-field loop most likely to hide
 * a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_pppoe_parser fuzz_pppoe_parser.c
 * Run:   ./fuzz_pppoe_parser fuzz_seeds/pppoe/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_pppoe_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    bool is_discovery = (Data[0] & 0x01) != 0;   /* fuzz both stages */
    pppoe_dissect_ethertype_payload(Data, (uint16_t)Size, is_discovery);

    return 0;
}
