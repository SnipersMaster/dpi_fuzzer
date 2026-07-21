/*
 * fuzz_6in4_parser.c
 *
 * libFuzzer harness for dpi_6in4_parser.c, including its inner-IPv6
 * dissection (reuses dpi_ipv6_parser.c and dpi_app_classifier.c,
 * already fuzzed independently by fuzz_ipv6_parser.c — this harness
 * adds coverage for the 6in4-specific detect()/dissect() wrapper).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_6in4_parser fuzz_6in4_parser.c
 * Run:   ./fuzz_6in4_parser fuzz_seeds/6in4/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_rfc_parser.c"
#include "dpi_ipv6_parser.c"
#include "dpi_tcp_flow_reassembly.c"
#include "dpi_app_classifier.c"
#include "dpi_dissector_registry.c"
#include "dpi_6in4_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = sixin4_detect(Data, (uint16_t)Size, 0, "");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    sixin4_dissect(Data, (uint16_t)Size, 0, "", &out);

    return 0;
}
