/*
 * fuzz_tcp_reassembly.c
 *
 * libFuzzer harness for dpi_tcp_flow_reassembly.c. Unlike the RFC
 * parser harness, this target is STATEFUL — a single segment tells
 * you almost nothing interesting; the overlap-resolution and evasion-
 * detection logic only gets exercised by a SEQUENCE of segments with
 * varying seq/length/content relative to each other. This harness
 * derives such a sequence from the fuzz input rather than fuzzing one
 * call in isolation.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_tcp_reassembly fuzz_tcp_reassembly.c
 * Run:   ./fuzz_tcp_reassembly fuzz_seeds/tcp_reassembly/ -max_len=4096
 *
 * NOT RUN in this environment — reviewed but not executed, same
 * caveat as every other harness in this set.
 *
 * -------------------------------------------------------------------
 * INPUT FORMAT (designed for libFuzzer's mutator to explore easily —
 * small integer fields, no checksums or anything a byte-flip mutation
 * would need to "get lucky" past):
 * -------------------------------------------------------------------
 *   byte 0:       overlap policy (bit 0: 0=FIRST_WINS, 1=LAST_WINS)
 *   byte 1:       number of segments to feed (capped, see MAX_SEGMENTS)
 *   then, repeated per segment:
 *     4 bytes:    relative seq offset (interpreted as int32, added to
 *                 a running base so segments can go backward/forward/
 *                 overlap — this is deliberately not just "next byte",
 *                 since out-of-order and overlapping delivery is
 *                 exactly what needs stressing here)
 *     1 byte:     segment length (0-64, capped — small on purpose so
 *                 many segments fit in one fuzz input and overlaps
 *                 between them are likely, not rare)
 *     N bytes:    segment data (truncated to whatever input remains)
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "dpi_tcp_flow_reassembly.c"

#define MAX_SEGMENTS   32
#define MAX_SEG_LEN    64
#define FUZZ_PARTITION 0   /* dedicated partition, reset every call —
                             * see tcp_reassembly_reset_partition_for_testing() */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    enum tcp_overlap_policy policy =
        (Data[0] & 0x01) ? TCP_OVERLAP_LAST_WINS : TCP_OVERLAP_FIRST_WINS;
    uint8_t n_segments = Data[1] % MAX_SEGMENTS;

    size_t pos = 2;
    uint32_t running_seq = 1000;   /* arbitrary nonzero base */

    struct tcp_flow_key key = tcp_flow_key_make_v4(0x0A000001, 0x0A000002, 51234, 443);

    for (uint8_t i = 0; i < n_segments; i++) {
        if (pos + 5 > Size) break;   /* not enough input left for another segment header */

        int32_t seq_delta;
        memcpy(&seq_delta, Data + pos, 4);
        pos += 4;

        uint8_t seg_len = Data[pos] % (MAX_SEG_LEN + 1);
        pos += 1;

        if (pos + seg_len > Size) {
            seg_len = (uint8_t)(Size - pos);   /* truncate to what's left, don't skip the segment */
        }

        running_seq = (uint32_t)((int64_t)running_seq + seq_delta);

        const uint8_t *contiguous_data = NULL;
        uint32_t contiguous_len = 0;
        struct tcp_reassembly_stats stats;

        tcp_reassembly_insert(FUZZ_PARTITION, &key, running_seq,
                               Data + pos, seg_len, policy,
                               &contiguous_data, &contiguous_len, &stats);

        pos += seg_len;
    }

    /* Reset before returning, not just at the start — ensures no
     * state leaks into whatever iteration libFuzzer runs next,
     * regardless of how this one exited (including early break above). */
    tcp_reassembly_reset_partition_for_testing(FUZZ_PARTITION);

    return 0;
}
