/*
 * fuzz_ssh_parser.c
 *
 * libFuzzer harness for dpi_ssh_parser.c. The KEXINIT namelist parsing
 * (ssh_read_namelist, called 8 times per KEXINIT packet) is the
 * highest-value target here — repeated length-prefixed field parsing
 * over attacker-controlled offsets, similar in spirit to why DNS name
 * decompression got extra scrutiny. Plaintext, no crypto boundary
 * (SSH's actual encrypted session starts only after key exchange
 * completes).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_ssh_parser fuzz_ssh_parser.c
 * Run:   ./fuzz_ssh_parser fuzz_seeds/ssh/ -max_len=2048
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_ssh_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 2048) return 0;

    double confidence = ssh_detect(Data, (uint16_t)Size, 22, "TCP");
    if (confidence <= 0.3) return 0;

    struct dissect_result out;
    ssh_dissect(Data, (uint16_t)Size, 22, "TCP", &out);

    return 0;
}
