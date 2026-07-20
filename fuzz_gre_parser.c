/*
 * fuzz_gre_parser.c
 *
 * libFuzzer harness for dpi_gre_parser.c, including its recursive
 * decapsulation into inner IPv4/IPv6 (and the bounded GRE-in-GRE
 * nesting path) — this harness needs the same dependency chain GTP's
 * inner-packet recursion needed (dpi_app_classifier.c for SNI
 * extraction, dpi_rfc_parser.c and dpi_ipv6_parser.c for the inner
 * IP/TCP/UDP parsing).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_gre_parser fuzz_gre_parser.c
 * Run:   ./fuzz_gre_parser fuzz_seeds/gre/ -max_len=1500
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
#include "dpi_gre_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1500) return 0;

    double confidence = gre_detect(Data, (uint16_t)Size, 0, "GRE");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    gre_dissect(Data, (uint16_t)Size, 0, "GRE", &out);

    return 0;
}
