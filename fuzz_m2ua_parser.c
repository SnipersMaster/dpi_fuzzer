/*
 * fuzz_m2ua_parser.c
 *
 * libFuzzer harness for dpi_m2ua_parser.c. The TLV parameter walk is
 * exactly the kind of variable-length-field loop most likely to hide
 * a bounds bug — same reasoning as fuzz_m3ua_parser.c, whose harness
 * this one mirrors exactly (M2UA and M3UA share the identical common
 * header and TLV framing).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_m2ua_parser fuzz_m2ua_parser.c
 * Run:   ./fuzz_m2ua_parser fuzz_seeds/m2ua/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_m2ua_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = m2ua_detect(Data, (uint16_t)Size, 2, "SCTP-DATA");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    m2ua_dissect(Data, (uint16_t)Size, 2, "SCTP-DATA", &out);

    return 0;
}
