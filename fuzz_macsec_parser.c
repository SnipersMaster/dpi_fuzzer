/*
 * fuzz_macsec_parser.c
 *
 * libFuzzer harness for dpi_macsec_parser.c. Targets
 * macsec_dissect_ethertype_payload() directly — MACsec is detected
 * via a real EtherType (0x88E5) inside dispatch_by_ethertype(), not
 * the normal registry. The conditional SCI field (only present when
 * a bit in TCI_AN is set) is exactly the kind of variable-length
 * structure most likely to hide a bounds bug if the presence check
 * and the length check ever disagree.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_macsec_parser fuzz_macsec_parser.c
 * Run:   ./fuzz_macsec_parser fuzz_seeds/macsec/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_macsec_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    macsec_dissect_ethertype_payload(Data, (uint16_t)Size);

    return 0;
}
