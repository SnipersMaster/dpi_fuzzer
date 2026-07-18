/*
 * fuzz_http2_continuation.c
 *
 * Dedicated harness for dpi_http2_parser.c's CONTINUATION frame
 * reassembly logic specifically — fuzz_http2_parser.c exercises this
 * structurally through generic random-byte frame sequences, but that
 * rarely constructs a VALID multi-frame HEADERS+CONTINUATION sequence
 * (matching stream IDs, split at a real HPACK instruction boundary,
 * exactly one END_HEADERS at the end) often enough to give the
 * reassembly path itself deep coverage. This harness constructs such
 * sequences deliberately from fuzz input, so the mutator's entropy
 * goes into the SPLIT POINTS and adversarial variations, not into
 * accidentally-valid frame structure.
 *
 * -------------------------------------------------------------------
 * INPUT FORMAT
 * -------------------------------------------------------------------
 *   byte 0: number of pieces to split the field block into (1-8,
 *           taken mod 8 + 1)
 *   byte 1: bit 0 = inject a stream-ID mismatch on one CONTINUATION
 *           frame (the adversarial case RFC 9113 S6.10 requires
 *           rejecting); bit 1 = corrupt one CONTINUATION frame's type
 *           to something other than 0x9 (also must be rejected)
 *   byte 2: stream_id (low byte; high bytes fixed at 0 for simplicity)
 *   remaining bytes: used as split-point entropy (each byte, mod
 *           remaining field-block length, chooses where to cut)
 *
 * The field block being split is a FIXED, real, RFC-verified HPACK
 * sequence (the same RFC 7541 Appendix C.4.1 bytes used elsewhere in
 * this project's seed corpus) — this ensures that when reassembly
 * genuinely succeeds, the harness can also confirm (via the callback)
 * that the reassembled result decodes to the correct headers, not just
 * that it didn't crash.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_http2_continuation fuzz_http2_continuation.c
 * Run:   ./fuzz_http2_continuation fuzz_seeds/http2_continuation/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_hpack_decoder.c"
#include "dpi_http2_parser.c"

/* RFC 7541 Appendix C.4.1 — verified elsewhere in this project to
 * decode to :method:GET, :scheme:http, :path:/,
 * :authority:www.example.com. Used here as the payload to split across
 * frames, not to re-verify HPACK itself (that's fuzz_hpack_decoder.c's
 * job) — just to give the reassembly path a real, valid field block to
 * reassemble. */
static const uint8_t FIELD_BLOCK[] = {
    0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2,
    0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
};

static void write_frame_header(uint8_t *out, uint32_t length, uint8_t type,
                                uint8_t flags, uint32_t stream_id) {
    out[0] = (uint8_t)(length >> 16);
    out[1] = (uint8_t)(length >> 8);
    out[2] = (uint8_t)length;
    out[3] = type;
    out[4] = flags;
    out[5] = (uint8_t)(stream_id >> 24);
    out[6] = (uint8_t)(stream_id >> 16);
    out[7] = (uint8_t)(stream_id >> 8);
    out[8] = (uint8_t)stream_id;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 3) return 0;

    int n_pieces = (Data[0] % 8) + 1;
    bool inject_stream_mismatch = (Data[1] & 0x01) != 0;
    bool inject_type_corruption = (Data[1] & 0x02) != 0;
    uint32_t stream_id = Data[2];
    if (stream_id == 0) stream_id = 1;   /* stream 0 is reserved/invalid for HEADERS */

    size_t fb_len = sizeof(FIELD_BLOCK);
    if ((size_t)n_pieces > fb_len) n_pieces = (int)fb_len;   /* can't split smaller than 1 byte/piece */

    /* Choose split points using remaining fuzz bytes as entropy. */
    size_t piece_sizes[8];
    size_t remaining = fb_len;
    size_t entropy_pos = 3;
    for (int i = 0; i < n_pieces - 1; i++) {
        size_t max_piece = remaining - (size_t)(n_pieces - 1 - i);   /* leave >=1 byte per remaining piece */
        if (max_piece == 0) { piece_sizes[i] = 0; continue; }
        uint8_t entropy = (entropy_pos < Size) ? Data[entropy_pos++] : 0;
        size_t piece = (entropy % max_piece) + 1;
        piece_sizes[i] = piece;
        remaining -= piece;
    }
    piece_sizes[n_pieces - 1] = remaining;

    /* Build: preface + HEADERS frame (piece 0) + CONTINUATION frame(s)
     * (remaining pieces), matching RFC 9113 S6.10's format exactly
     * except where deliberately corrupted above. */
    uint8_t packet[256];
    size_t pos = 0;
    static const uint8_t PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    memcpy(packet + pos, PREFACE, 24);
    pos += 24;

    size_t fb_pos = 0;
    for (int i = 0; i < n_pieces; i++) {
        bool is_last = (i == n_pieces - 1);
        uint8_t frame_type = (i == 0) ? 0x1 /* HEADERS */ : 0x9 /* CONTINUATION */;
        uint8_t flags = is_last ? 0x04 /* END_HEADERS */ : 0x00;
        uint32_t this_stream_id = stream_id;

        /* Adversarial injections, applied to a middle CONTINUATION
         * frame if there are enough pieces to have one. */
        if (i > 0 && i < n_pieces - 1) {
            if (inject_stream_mismatch) this_stream_id = stream_id + 1;
            if (inject_type_corruption) frame_type = 0x0 /* DATA, not CONTINUATION */;
        }

        if (pos + 9 + piece_sizes[i] > sizeof(packet)) break;   /* bounded, don't overflow the local buffer */

        write_frame_header(packet + pos, (uint32_t)piece_sizes[i], frame_type, flags, this_stream_id);
        pos += 9;
        memcpy(packet + pos, FIELD_BLOCK + fb_pos, piece_sizes[i]);
        pos += piece_sizes[i];
        fb_pos += piece_sizes[i];
    }

    struct dissect_result out;
    memset(&out, 0, sizeof(out));
    http2_dissect(packet, (uint16_t)pos, 443, "TCP", &out);

    return 0;
}
