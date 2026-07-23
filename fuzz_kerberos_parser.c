/*
 * fuzz_kerberos_parser.c
 *
 * libFuzzer harness for dpi_kerberos_parser.c, covering the ASN.1 BER
 * length-walking (message-type detection and KRB-ERROR's error-code
 * extraction).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_kerberos_parser fuzz_kerberos_parser.c
 * Run:   ./fuzz_kerberos_parser fuzz_seeds/kerberos/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_kerberos_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = kerberos_detect(Data, (uint16_t)Size, 88, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    kerberos_dissect(Data, (uint16_t)Size, 88, "TCP", &out);

    return 0;
}
