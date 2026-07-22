/*
 * fuzz_smb1_parser.c
 *
 * libFuzzer harness for dpi_smb1_parser.c, covering the fixed header,
 * word-count/byte-count bounds checking, and the Negotiate Protocol
 * dialect-list walk.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_smb1_parser fuzz_smb1_parser.c
 * Run:   ./fuzz_smb1_parser fuzz_seeds/smb1/ -max_len=1024
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_smb1_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1024) return 0;

    double confidence = smb1_detect(Data, (uint16_t)Size, 445, "TCP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    smb1_dissect(Data, (uint16_t)Size, 445, "TCP", &out);

    return 0;
}
