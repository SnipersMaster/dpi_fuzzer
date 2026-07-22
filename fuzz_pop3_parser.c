/*
 * fuzz_pop3_parser.c
 *
 * libFuzzer harness for dpi_pop3_parser.c. Plaintext, no crypto
 * boundary, no capture-path dependency chain needed.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_pop3_parser fuzz_pop3_parser.c
 * Run:   ./fuzz_pop3_parser fuzz_seeds/pop3/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_pop3_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double conf_cmd = pop3_detect(Data, (uint16_t)Size, 110, "TCP");
    if (conf_cmd > 0.15) {
        struct dissect_result out;
        pop3_dissect(Data, (uint16_t)Size, 110, "TCP", &out);
    }

    double conf_resp = pop3_detect(Data, (uint16_t)Size, 51234, "TCP");
    if (conf_resp > 0.15) {
        struct dissect_result out2;
        pop3_dissect(Data, (uint16_t)Size, 51234, "TCP", &out2);
    }

    return 0;
}
