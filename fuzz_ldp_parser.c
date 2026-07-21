/*
 * fuzz_ldp_parser.c
 *
 * libFuzzer harness for dpi_ldp_parser.c, covering both UDP (Hello
 * discovery) and TCP (session) transports and the multi-message-per-
 * buffer walk (confirmed necessary against real traffic — see the
 * file's own header comment).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_ldp_parser fuzz_ldp_parser.c
 * Run:   ./fuzz_ldp_parser fuzz_seeds/ldp/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_ldp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    double conf_udp = ldp_detect(Data, (uint16_t)Size, 646, "UDP");
    if (conf_udp > 0.15) {
        struct dissect_result out;
        ldp_dissect(Data, (uint16_t)Size, 646, "UDP", &out);
    }

    double conf_tcp = ldp_detect(Data, (uint16_t)Size, 646, "TCP");
    if (conf_tcp > 0.15) {
        struct dissect_result out2;
        ldp_dissect(Data, (uint16_t)Size, 646, "TCP", &out2);
    }

    return 0;
}
