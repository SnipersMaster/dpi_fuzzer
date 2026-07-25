/*
 * fuzz_rtsp_parser.c
 *
 * libFuzzer harness for dpi_rtsp_parser.c. The line-finding and
 * header-walking loops are exactly the kind of variable-length
 * text-protocol parsing most likely to hide a bounds bug — same
 * reasoning as this project's existing fuzz_sip_rtp_parser.c and
 * HTTP/1.1 harnesses.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_rtsp_parser fuzz_rtsp_parser.c
 * Run:   ./fuzz_rtsp_parser fuzz_seeds/rtsp/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_rtsp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    double confidence = rtsp_detect(Data, (uint16_t)Size, 554, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    rtsp_dissect(Data, (uint16_t)Size, 554, "TCP", &out);

    return 0;
}
