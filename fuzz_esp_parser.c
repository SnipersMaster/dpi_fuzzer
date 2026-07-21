/*
 * fuzz_esp_parser.c
 *
 * libFuzzer harness for dpi_esp_parser.c. Trivial fixed-header
 * extraction (SPI + sequence number), no crypto boundary since
 * nothing past the header is ever parsed.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_esp_parser fuzz_esp_parser.c
 * Run:   ./fuzz_esp_parser fuzz_seeds/esp/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_esp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 64) return 0;

    double confidence = esp_detect(Data, (uint16_t)Size, 0, "");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    esp_dissect(Data, (uint16_t)Size, 0, "", &out);

    return 0;
}
