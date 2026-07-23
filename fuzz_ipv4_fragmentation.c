/*
 * fuzz_ipv4_fragmentation.c
 *
 * libFuzzer harness targeting IPv4 fragmentation reassembly
 * specifically (`frag_insert`/`frag_find_or_create` in
 * dpi_rfc_parser.c via `parse_ipv4`), added after real-traffic
 * verification found two real bugs in this logic — one a severe,
 * previously undisclosed 100%-failure-rate bug (the completion check
 * could never succeed for realistically-sized datagrams), the other
 * an already-disclosed gap (mid-hole fragment insertion needing a
 * split) confirmed to matter under real out-of-order arrival. See
 * `frag_insert()`'s own header comment in dpi_rfc_parser.c for the
 * full story. This harness exists specifically because that logic
 * had no fuzz coverage at all before now, despite being exactly the
 * kind of stateful, bounded-array logic (hole-list manipulation via
 * memmove, a fixed-size flow table) most likely to have subtle
 * off-by-one or bounds errors that a single verification pass might
 * not catch.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_ipv4_fragmentation fuzz_ipv4_fragmentation.c
 * Run:   ./fuzz_ipv4_fragmentation fuzz_seeds/ipv4_fragmentation/ -max_len=1500
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>

#include "dpi_rfc_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 20 || Size > 1500) return 0;

    struct ipv4_result out;
    /* Deliberately not checking the return value or output fields —
     * this harness exists purely to exercise frag_insert()'s bounded
     * array/memmove logic under arbitrary (including malformed and
     * adversarial-looking) fragment offset/length/flag combinations
     * without crashing, not to verify correctness (already verified
     * separately against real, known-good fragments in Python). */
    parse_ipv4(Data, (uint16_t)Size, &out);

    return 0;
}
