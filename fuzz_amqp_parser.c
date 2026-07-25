/*
 * fuzz_amqp_parser.c
 *
 * libFuzzer harness for dpi_amqp_parser.c. The frame-end-marker walk
 * and shortstr argument parsing are exactly the kind of length-
 * prefixed, variable-length-field logic most likely to hide a bounds
 * bug — same reasoning as this project's other TLV/frame-walking
 * harnesses.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_amqp_parser fuzz_amqp_parser.c
 * Run:   ./fuzz_amqp_parser fuzz_seeds/amqp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_amqp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = amqp_detect(Data, (uint16_t)Size, 5672, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    amqp_dissect(Data, (uint16_t)Size, 5672, "TCP", &out);

    return 0;
}
