/*
 * fuzz_netbios_parser.c
 *
 * libFuzzer harness for dpi_netbios_parser.c, covering both NBNS
 * (port 137) and NBDS (port 138) code paths, including the shared
 * first-level NetBIOS name decoder.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_netbios_parser fuzz_netbios_parser.c
 * Run:   ./fuzz_netbios_parser fuzz_seeds/netbios/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_netbios_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double conf_nbns = netbios_detect(Data, (uint16_t)Size, 137, "UDP");
    if (conf_nbns > 0.15) {
        struct dissect_result out;
        netbios_dissect(Data, (uint16_t)Size, 137, "UDP", &out);
    }

    double conf_nbds = netbios_detect(Data, (uint16_t)Size, 138, "UDP");
    if (conf_nbds > 0.15) {
        struct dissect_result out2;
        netbios_dissect(Data, (uint16_t)Size, 138, "UDP", &out2);
    }

    return 0;
}
