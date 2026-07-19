/*
 * fuzz_arp_parser.c
 *
 * libFuzzer harness for dpi_arp_parser.c. Plaintext, no crypto boundary.
 * Built to close a gap found during a later integration pass: this
 * dissector existed and was registered but had no fuzz harness yet,
 * unlike every other dissector in this project.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_arp_parser fuzz_arp_parser.c
 * Run:   ./fuzz_arp_parser fuzz_seeds/arp/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_arp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 64) return 0;

    double confidence = arp_detect(Data, (uint16_t)Size, 0, "ARP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    arp_dissect(Data, (uint16_t)Size, 0, "ARP", &out);

    return 0;
}
