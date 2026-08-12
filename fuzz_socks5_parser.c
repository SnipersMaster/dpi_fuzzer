/*
 * fuzz_socks5_parser.c
 *
 * libFuzzer harness for dpi_socks5_parser.c. All 3 address types
 * (IPv4/domain/IPv6) plus the variable-length domain-name field are
 * exactly the kind of branching, variable-length parsing most likely
 * to hide a bounds bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_socks5_parser fuzz_socks5_parser.c
 * Run:   ./fuzz_socks5_parser fuzz_seeds/socks5/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_socks5_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = socks5_detect(Data, (uint16_t)Size, 1080, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    socks5_dissect(Data, (uint16_t)Size, 1080, "TCP", &out);

    return 0;
}
