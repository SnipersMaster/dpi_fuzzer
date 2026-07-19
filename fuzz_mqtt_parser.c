/*
 * fuzz_mqtt_parser.c
 *
 * libFuzzer harness for dpi_mqtt_parser.c. Plaintext, no crypto
 * boundary. Closes the same "existed, registered, but never fuzzed"
 * gap as fuzz_arp_parser.c.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_mqtt_parser fuzz_mqtt_parser.c
 * Run:   ./fuzz_mqtt_parser fuzz_seeds/mqtt/ -max_len=2048
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_mqtt_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 2048) return 0;

    double confidence = mqtt_detect(Data, (uint16_t)Size, 1883, "TCP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    mqtt_dissect(Data, (uint16_t)Size, 1883, "TCP", &out);

    return 0;
}
