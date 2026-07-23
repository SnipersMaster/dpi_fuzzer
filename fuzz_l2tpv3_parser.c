/*
 * fuzz_l2tpv3_parser.c
 *
 * libFuzzer harness for dpi_l2tpv3_parser.c, including its recursive
 * inner-IPv4/TCP/SNI dissection path.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_l2tpv3_parser fuzz_l2tpv3_parser.c
 * Run:   ./fuzz_l2tpv3_parser fuzz_seeds/l2tpv3/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#include "dpi_rfc_parser.c"
#include "dpi_ipv6_parser.c"
#include "dpi_tcp_flow_reassembly.c"
#include "dpi_app_classifier.c"
#include "dpi_dissector_registry.c"
#include "dpi_l2tpv3_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = l2tpv3_detect(Data, (uint16_t)Size, 0, "");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    l2tpv3_dissect(Data, (uint16_t)Size, 0, "", &out);

    return 0;
}
