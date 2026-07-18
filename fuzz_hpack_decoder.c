/*
 * fuzz_hpack_decoder.c
 *
 * libFuzzer harness for dpi_hpack_decoder.c directly — the HPACK
 * decoder is the highest-risk new component in this pass (a 257-entry
 * Huffman table, integer/string decoding with attacker-controlled
 * lengths, and a dynamic table with insertion/eviction logic). This
 * harness fuzzes hpack_decode_header_block() directly on raw bytes,
 * rather than only reaching it indirectly through HTTP/2 frame
 * parsing — the header block format itself has no crypto boundary
 * and no framing dependency, so direct fuzzing is both possible and
 * more efficient than going through the frame layer first.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_hpack_decoder fuzz_hpack_decoder.c
 * Run:   ./fuzz_hpack_decoder fuzz_seeds/hpack/ -max_len=4096
 *
 * NOT RUN in this environment — reviewed but not executed. Given this
 * decoder's Huffman table and integer/string parsing are genuinely new
 * and higher-risk than most of this project's other plaintext
 * dissectors, this harness is worth prioritizing early.
 */

#include <stdint.h>
#include <stddef.h>

#include "dpi_hpack_decoder.c"

static void noop_header_callback(const char *name, const char *value, void *user_ctx) {
    (void)name; (void)value; (void)user_ctx;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 4096) return 0;

    bool dyn_miss = false;
    hpack_decode_header_block_fresh(Data, Size, 4096, noop_header_callback, NULL, &dyn_miss);

    return 0;
}
