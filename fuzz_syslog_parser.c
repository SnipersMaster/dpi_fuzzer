/*
 * fuzz_syslog_parser.c
 *
 * libFuzzer harness for dpi_syslog_parser.c, covering both UDP (port
 * 514) and TCP (port 601) transports and the multi-message-per-buffer
 * walk (implemented per RFC 6587, though real traffic in this
 * project's verification capture never exercised more than one
 * message per segment — see the file's own header comment).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_syslog_parser fuzz_syslog_parser.c
 * Run:   ./fuzz_syslog_parser fuzz_seeds/syslog/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_syslog_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    double conf_udp = syslog_detect(Data, (uint16_t)Size, 514, "UDP");
    if (conf_udp > 0.15) {
        struct dissect_result out;
        syslog_dissect(Data, (uint16_t)Size, 514, "UDP", &out);
    }

    double conf_tcp = syslog_detect(Data, (uint16_t)Size, 601, "TCP");
    if (conf_tcp > 0.15) {
        struct dissect_result out2;
        syslog_dissect(Data, (uint16_t)Size, 601, "TCP", &out2);
    }

    return 0;
}
