/*
 * fuzz_bt_dht_parser.c
 *
 * libFuzzer harness for dpi_bt_dht_parser.c. Bencoding's recursive
 * dict/list structure and length-prefixed strings make this exactly
 * the kind of variable-length-field format most likely to hide a
 * bounds bug (same reasoning as the SNMP/LDAP/Kerberos BER harnesses
 * and HTTP/2's frame-walking harness) — worth fuzzing thoroughly
 * despite the clean 126,321/126,321 real-traffic verification.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_bt_dht_parser fuzz_bt_dht_parser.c
 * Run:   ./fuzz_bt_dht_parser fuzz_seeds/bt_dht/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_bt_dht_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    double confidence = bt_dht_detect(Data, (uint16_t)Size, 6881, "UDP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    bt_dht_dissect(Data, (uint16_t)Size, 6881, "UDP", &out);

    return 0;
}
