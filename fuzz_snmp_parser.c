/*
 * fuzz_snmp_parser.c
 *
 * libFuzzer harness for dpi_snmp_parser.c. Plaintext BER/ASN.1
 * decoding — no crypto boundary, but ASN.1 parsing is a different
 * paradigm from the fixed-field/simple-TLV parsing used elsewhere in
 * this project, worth fuzzing carefully. Closes the same "existed,
 * registered, but never fuzzed" gap as fuzz_arp_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_snmp_parser fuzz_snmp_parser.c
 * Run:   ./fuzz_snmp_parser fuzz_seeds/snmp/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_snmp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    double confidence = snmp_detect(Data, (uint16_t)Size, 161, "UDP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    snmp_dissect(Data, (uint16_t)Size, 161, "UDP", &out);

    return 0;
}
