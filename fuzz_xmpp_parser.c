/*
 * fuzz_xmpp_parser.c
 *
 * libFuzzer harness for dpi_xmpp_parser.c. The attribute-value search
 * (xmpp_find_attr, bounded but still a variable-position scan) is
 * exactly the kind of text-parsing logic most likely to hide a bounds
 * bug.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_xmpp_parser fuzz_xmpp_parser.c
 * Run:   ./fuzz_xmpp_parser fuzz_seeds/xmpp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_xmpp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = xmpp_detect(Data, (uint16_t)Size, 5222, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    xmpp_dissect(Data, (uint16_t)Size, 5222, "TCP", &out);

    return 0;
}
