/*
 * fuzz_ftp_parser.c
 *
 * libFuzzer harness for dpi_ftp_parser.c. Plaintext, no crypto
 * boundary — but the seed corpus specifically includes real
 * post-AUTH-TLS encrypted bytes from a genuine capture, to make sure
 * fuzzing keeps exercising the "correctly reject non-printable data"
 * path this dissector's whole design depends on (see the file's own
 * header comment for why that matters).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_ftp_parser fuzz_ftp_parser.c
 * Run:   ./fuzz_ftp_parser fuzz_seeds/ftp/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_ftp_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    /* Exercise both directions — command parsing (dst_port=21) and
     * response parsing (dst_port=some ephemeral client port). */
    double conf_cmd = ftp_detect(Data, (uint16_t)Size, 21, "TCP");
    if (conf_cmd > 0.15) {
        struct dissect_result out;
        ftp_dissect(Data, (uint16_t)Size, 21, "TCP", &out);
    }

    double conf_resp = ftp_detect(Data, (uint16_t)Size, 51234, "TCP");
    if (conf_resp > 0.15) {
        struct dissect_result out2;
        ftp_dissect(Data, (uint16_t)Size, 51234, "TCP", &out2);
    }

    return 0;
}
