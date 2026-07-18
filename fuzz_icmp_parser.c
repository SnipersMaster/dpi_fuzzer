/*
 * fuzz_icmp_parser.c
 *
 * libFuzzer harness for dpi_icmp_parser.c (both ICMPv4 and ICMPv6).
 * Plaintext, no crypto boundary. Note: ICMPv6 checksum verification
 * lives in the capture path (needs IPv6 addresses the generic
 * dissector interface doesn't pass through — see dpi_icmp_parser.c's
 * header comment), so this harness exercises everything EXCEPT that
 * checksum path; icmpv6_dissect() itself is still fully exercised.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_icmp_parser fuzz_icmp_parser.c
 * Run:   ./fuzz_icmp_parser fuzz_seeds/icmp/ -max_len=1500
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_icmp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1500) return 0;

    /* Exercise both ICMPv4 and ICMPv6 from the same input. */
    double conf1 = icmpv4_detect(Data, (uint16_t)Size, 0, "ICMP");
    if (conf1 > 0.3) {
        struct dissect_result out1;
        icmpv4_dissect(Data, (uint16_t)Size, 0, "ICMP", &out1);
    }

    double conf2 = icmpv6_detect(Data, (uint16_t)Size, 0, "ICMPv6");
    if (conf2 > 0.3) {
        struct dissect_result out2;
        icmpv6_dissect(Data, (uint16_t)Size, 0, "ICMPv6", &out2);
    }

    return 0;
}
