/*
 * fuzz_eapol_parser.c
 *
 * libFuzzer harness for dpi_eapol_parser.c. Targets
 * eapol_dissect_ethertype_payload() directly — EAPOL is detected via
 * a real EtherType (0x888E) inside dispatch_by_ethertype(), not the
 * normal registry.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_eapol_parser fuzz_eapol_parser.c
 * Run:   ./fuzz_eapol_parser fuzz_seeds/eapol/ -max_len=128
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_eapol_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 128) return 0;

    eapol_dissect_ethertype_payload(Data, (uint16_t)Size);

    return 0;
}
