/*
 * fuzz_ldap_parser.c
 *
 * libFuzzer harness for dpi_ldap_parser.c, covering both the TCP
 * (multi-message-per-buffer, unverified against real traffic — see
 * the file's own header comment) and UDP/CLDAP (real-traffic-
 * verified) code paths — both flow through the same ldap_dissect().
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_ldap_parser fuzz_ldap_parser.c
 * Run:   ./fuzz_ldap_parser fuzz_seeds/ldap/ -max_len=2048
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_ldap_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 2048) return 0;

    /* Exercise both transports the dissector accepts. */
    double confidence_tcp = ldap_detect(Data, (uint16_t)Size, 389, "TCP");
    if (confidence_tcp > 0.15) {
        struct dissect_result out;
        ldap_dissect(Data, (uint16_t)Size, 389, "TCP", &out);
    }

    double confidence_udp = ldap_detect(Data, (uint16_t)Size, 389, "UDP");
    if (confidence_udp > 0.15) {
        struct dissect_result out2;
        ldap_dissect(Data, (uint16_t)Size, 389, "UDP", &out2);
    }

    return 0;
}
