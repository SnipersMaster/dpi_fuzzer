/*
 * fuzz_rfc_parser.c
 *
 * libFuzzer harness for dpi_rfc_parser.c's IPv4 -> TCP/UDP chain. All
 * of this is legitimately attacker-controlled plaintext with no crypto
 * boundary in front of it, so raw-byte fuzzing is the right approach
 * here — unlike QUIC, there's nothing to split the harness around.
 *
 * Build (see fuzz_build.sh for the full set of commands):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *       -o fuzz_rfc_parser fuzz_rfc_parser.c
 *
 * Run:
 *   ./fuzz_rfc_parser fuzz_seeds/rfc_parser/ -max_len=2048
 *
 * NOT RUN in this environment — no clang/libFuzzer available in this
 * sandbox. This harness has been reviewed but not executed; treat any
 * claim about what it would find as speculative until you actually
 * run it.
 */

#include <stdint.h>
#include <stddef.h>

/* Same file this project's capture paths include directly. */
#include "dpi_rfc_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* KNOWN CAVEAT: dpi_rfc_parser.c's IPv4 fragment cache (frag_table)
     * has no timeout eviction (documented gap, see the README's status
     * table for dpi_rfc_parser.c). Over a very long fuzzing run, inputs
     * that look like fragments could exhaust FRAG_MAX_FLOWS and reduce
     * coverage of fragment-related code paths in later iterations —
     * not a crash, just reduced effectiveness. Worth fixing that gap
     * (timeout eviction) before relying on many CPU-hours of fuzzing
     * to properly exercise the fragmentation path specifically.
     */
    if (Size < 1 || Size > 65535) return 0;

    struct ipv4_result ip_result;
    if (!parse_ipv4(Data, (uint16_t)Size, &ip_result)) return 0;

    if (ip_result.protocol == 6 /* TCP */) {
        struct tcp_result tcp_result;
        /* src/dst addr feed the pseudo-header checksum — using values
         * derived from the parsed IP header (as the real caller would)
         * rather than fixed constants, so checksum-dependent code paths
         * get exercised with values matching what parse_ipv4 saw. */
        parse_tcp(ip_result.src_addr, ip_result.dst_addr,
                   ip_result.payload, ip_result.payload_len, &tcp_result);
    } else if (ip_result.protocol == 17 /* UDP */) {
        struct udp_result udp_result;
        parse_udp(ip_result.src_addr, ip_result.dst_addr,
                   ip_result.payload, ip_result.payload_len, &udp_result);
    }

    return 0;
}
