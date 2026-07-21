/*
 * fuzz_telnet_parser.c
 *
 * libFuzzer harness for dpi_telnet_parser.c, covering both plain-text
 * data and IAC option-negotiation/subnegotiation paths.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_telnet_parser fuzz_telnet_parser.c
 * Run:   ./fuzz_telnet_parser fuzz_seeds/telnet/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_telnet_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = telnet_detect(Data, (uint16_t)Size, 23, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    telnet_dissect(Data, (uint16_t)Size, 23, "TCP", &out);

    return 0;
}
