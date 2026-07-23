/*
 * fuzz_whois_parser.c
 *
 * libFuzzer harness for dpi_whois_parser.c. Plaintext, no crypto
 * boundary, no capture-path dependency chain needed.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_whois_parser fuzz_whois_parser.c
 * Run:   ./fuzz_whois_parser fuzz_seeds/whois/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_whois_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double conf_query = whois_detect(Data, (uint16_t)Size, 43, "TCP");
    if (conf_query > 0.15) {
        struct dissect_result out;
        whois_dissect(Data, (uint16_t)Size, 43, "TCP", &out);
    }

    double conf_resp = whois_detect(Data, (uint16_t)Size, 51234, "TCP");
    if (conf_resp > 0.15) {
        struct dissect_result out2;
        whois_dissect(Data, (uint16_t)Size, 51234, "TCP", &out2);
    }

    return 0;
}
