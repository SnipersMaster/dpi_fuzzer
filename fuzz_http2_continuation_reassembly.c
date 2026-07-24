/*
 * fuzz_http2_continuation_reassembly.c
 *
 * libFuzzer harness targeting dpi_http2_parser.c's cross-TCP-boundary
 * CONTINUATION reassembly SPECIFICALLY — the stateful path only
 * reachable through http2_dissect_with_flow_state(), which the
 * existing fuzz_http2_parser.c harness never calls (it only exercises
 * the registry-facing, connectionless http2_dissect() entry point).
 * Added alongside the mid-frame-split fix in dpi_http2_parser.c /
 * dpi_hpack_connection_state.c specifically because that new code
 * path — persisting one in-flight CONTINUATION frame's partial
 * payload across an arbitrary number of further deliveries — had zero
 * fuzz coverage before now, despite being exactly the kind of
 * stateful, multi-call logic most likely to have subtle bugs (same
 * reasoning as fuzz_tcp_reassembly.c and fuzz_ipv4_fragmentation.c
 * existing for their respective stateful reassembly logic).
 *
 * INPUT FORMAT (same "derive a sequence of deliveries from one fuzz
 * input" approach as fuzz_tcp_reassembly.c, for the same reason —
 * this target is stateful, one delivery in isolation exercises almost
 * nothing interesting):
 *   byte 0: number of deliveries to feed (capped, see MAX_DELIVERIES)
 *   then, repeated per delivery:
 *     2 bytes: delivery length (capped to MAX_DELIVERY_LEN, and to
 *              whatever input remains)
 *     N bytes: delivery data (truncated to whatever remains)
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_http2_continuation_reassembly \
 *            fuzz_http2_continuation_reassembly.c
 * Run:   ./fuzz_http2_continuation_reassembly \
 *            fuzz_seeds/http2_continuation_reassembly/ -max_len=4096
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_tcp_flow_reassembly.c"
#include "dpi_hpack_connection_state.c"
#include "dpi_http2_parser.c"

#define MAX_DELIVERIES     16
#define MAX_DELIVERY_LEN   512
#define FUZZ_PARTITION     0

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    uint8_t n_deliveries = Data[0] % MAX_DELIVERIES;
    size_t pos = 1;

    struct tcp_flow_key key = tcp_flow_key_make_v4(0x0A000001, 0x0A000002, 51234, 443);
    struct hpack_connection_entry *conn =
        hpack_get_connection_entry(FUZZ_PARTITION, &key);
    if (!conn) return 0;

    for (uint8_t i = 0; i < n_deliveries; i++) {
        if (pos + 2 > Size) break;

        uint16_t delivery_len = ((uint16_t)Data[pos] << 8) | Data[pos + 1];
        pos += 2;
        if (delivery_len > MAX_DELIVERY_LEN) delivery_len = MAX_DELIVERY_LEN;
        if (pos + delivery_len > Size) {
            delivery_len = (uint16_t)(Size - pos);   /* truncate, don't skip */
        }

        struct dissect_result out;
        http2_dissect_with_flow_state(Data + pos, delivery_len, conn, NULL, &out);

        pos += delivery_len;
    }

    /* Reset before returning, same reasoning as
     * tcp_reassembly_reset_partition_for_testing() — a long-running
     * fuzz process makes far more calls than any real deployment's
     * connection-table size assumes, and state must not leak between
     * otherwise-unrelated fuzz iterations. */
    hpack_conn_reset_partition_for_testing(FUZZ_PARTITION);
    tcp_reassembly_reset_partition_for_testing(FUZZ_PARTITION);

    return 0;
}
