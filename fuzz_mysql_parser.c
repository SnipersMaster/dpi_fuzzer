/*
 * fuzz_mysql_parser.c
 *
 * libFuzzer harness for dpi_mysql_parser.c. The Initial Handshake
 * packet's variable-length server-version string and subsequent
 * fixed-offset field reads are exactly the kind of parsing most
 * likely to hide a bounds bug if the NUL terminator search runs past
 * the buffer or a fixed-offset read isn't checked against what's
 * actually available.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_mysql_parser fuzz_mysql_parser.c
 * Run:   ./fuzz_mysql_parser fuzz_seeds/mysql/ -max_len=256
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_mysql_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 256) return 0;

    double confidence = mysql_detect(Data, (uint16_t)Size, 3306, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    mysql_dissect(Data, (uint16_t)Size, 3306, "TCP", &out);

    return 0;
}
