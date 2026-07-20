/*
 * fuzz_mpls_parser.c
 *
 * libFuzzer harness for dpi_mpls_parser.c, including the bounded
 * label-stack walk and decapsulation into inner IPv4/IPv6. Needs the
 * same dependency chain GRE's inner-packet recursion needed.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_mpls_parser fuzz_mpls_parser.c
 * Run:   ./fuzz_mpls_parser fuzz_seeds/mpls/ -max_len=1500
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
#include "dpi_mpls_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1500) return 0;

    double confidence = mpls_detect(Data, (uint16_t)Size, 0, "MPLS");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    mpls_dissect(Data, (uint16_t)Size, 0, "MPLS", &out);

    return 0;
}
