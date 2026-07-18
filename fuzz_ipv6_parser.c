/*
 * fuzz_ipv6_parser.c
 *
 * libFuzzer harness for dpi_ipv6_parser.c. The extension header chain
 * walker is the highest-value target here — verified by hand against
 * an adversarial 20-header chain earlier in this project (correctly
 * rejected via the MAX_EXT_HEADERS cap), but hand-verification of a
 * few cases is not a substitute for actual fuzzing across the full
 * input space. Plaintext, no crypto boundary.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_ipv6_parser fuzz_ipv6_parser.c
 * Run:   ./fuzz_ipv6_parser fuzz_seeds/ipv6/ -max_len=1500
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#include "dpi_rfc_parser.c"
#include "dpi_ipv6_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1500) return 0;

    struct ipv6_result ip6_result;
    if (!parse_ipv6(Data, (uint16_t)Size, &ip6_result)) return 0;

    if (ip6_result.next_header == 6 /* TCP */) {
        struct tcp_result tcp_result;
        parse_tcp_v6(ip6_result.src_addr, ip6_result.dst_addr,
                      ip6_result.payload, ip6_result.payload_len, &tcp_result);
    } else if (ip6_result.next_header == 17 /* UDP */) {
        struct udp_result udp_result;
        parse_udp_v6(ip6_result.src_addr, ip6_result.dst_addr,
                      ip6_result.payload, ip6_result.payload_len, &udp_result);
    }

    return 0;
}
