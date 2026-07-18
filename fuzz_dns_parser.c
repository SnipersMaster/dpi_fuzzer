/*
 * fuzz_dns_parser.c
 *
 * libFuzzer harness for dpi_dns_parser.c. The name-decompression logic
 * (dns_decode_name) is the highest-value target in this file — it's
 * exactly the kind of pointer-chasing-over-attacker-data logic that
 * has caused real DNS parser vulnerabilities historically (cyclic
 * pointers, OOB reads, quadratic blowup). This harness fuzzes the
 * whole detect()/dissect() path, which exercises that logic on every
 * input that gets past the initial structural check.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_dns_parser fuzz_dns_parser.c
 * Run:   ./fuzz_dns_parser fuzz_seeds/dns/ -max_len=512
 *
 * NOT RUN in this environment — reviewed but not executed. This one
 * in particular is worth prioritizing when you do run these, given
 * name decompression's history as a real-world bug source.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_dns_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;   /* DNS-over-UDP is practically
                                               * capped well under 512 for
                                               * anything without EDNS0 */

    double confidence = dns_detect(Data, (uint16_t)Size, 53, "UDP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    dns_dissect(Data, (uint16_t)Size, 53, "UDP", &out);

    return 0;
}
