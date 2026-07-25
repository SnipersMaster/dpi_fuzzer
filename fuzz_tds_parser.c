/*
 * fuzz_tds_parser.c
 *
 * libFuzzer harness for dpi_tds_parser.c. The PRELOGIN token walk
 * (Token/Offset/Length entries, where Offset points elsewhere in the
 * buffer rather than immediately following the entry itself) is
 * exactly the kind of indirect-offset parsing most likely to hide a
 * bounds bug — this dissector's own offset+length bounds check
 * (`offset + 4 <= body_len`) is precisely what a fuzzer is well
 * suited to stress.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_tds_parser fuzz_tds_parser.c
 * Run:   ./fuzz_tds_parser fuzz_seeds/tds/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_tds_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = tds_detect(Data, (uint16_t)Size, 1433, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    tds_dissect(Data, (uint16_t)Size, 1433, "TCP", &out);

    return 0;
}
