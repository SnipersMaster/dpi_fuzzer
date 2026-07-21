/*
 * fuzz_mdns_parser.c
 *
 * libFuzzer harness for dpi_mdns_parser.c, which reuses
 * dpi_dns_parser.c's name decompression directly — the DNS name-
 * decompression bounds (MAX_POINTER_JUMPS, MAX_DNS_NAME_LEN) already
 * fuzzed by fuzz_dns_parser.c apply here too, so this harness mainly
 * adds coverage for the QU-bit/cache-flush-bit extraction and the
 * QDCOUNT=0 announcement path that's distinctly mDNS.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_mdns_parser fuzz_mdns_parser.c
 * Run:   ./fuzz_mdns_parser fuzz_seeds/mdns/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_mdns_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    double confidence = mdns_detect(Data, (uint16_t)Size, 5353, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    mdns_dissect(Data, (uint16_t)Size, 5353, "UDP", &out);

    return 0;
}
