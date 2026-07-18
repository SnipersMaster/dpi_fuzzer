/*
 * fuzz_quic_header.c
 *
 * libFuzzer harness for dpi_quic_parser.c's PRE-DECRYPTION path: QUIC
 * long-header parsing, varint decoding (DCID/SCID lengths, token
 * length, payload length), key derivation, header protection removal,
 * and AAD/nonce construction. All of this runs on every input
 * regardless of whether AES-GCM authentication ultimately succeeds —
 * a bug in pointer arithmetic or a length check BEFORE the auth check
 * (e.g. in ct_len/ciphertext/tag offset computation) is exactly the
 * kind of thing this harness can catch even though decryption itself
 * will fail on nearly all random input.
 *
 * WHAT THIS HARNESS DELIBERATELY DOES NOT COVER: the frame-walking and
 * SNI-extraction logic that only runs after successful decryption.
 * Random bytes essentially never pass AES-GCM authentication (that's
 * the point of an AEAD), so naive fuzzing here would almost never
 * reach that code. See fuzz_quic_frames.c, which fuzzes that logic
 * directly by treating input as already-decrypted plaintext — the
 * standard way to fuzz test code on the far side of a crypto boundary
 * without needing the harness to construct valid ciphertext itself.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_quic_header fuzz_quic_header.c -lssl -lcrypto
 * Run:   ./fuzz_quic_header fuzz_seeds/quic_header/ -max_len=1500
 *
 * NOT RUN in this environment (no clang/libFuzzer, and no OpenSSL dev
 * headers in this sandbox either) — reviewed but not executed.
 */

#include <stdint.h>
#include <stddef.h>

/* dpi_quic_parser.c needs struct dissect_result / dissect_result_add()
 * from the registry, and extract_sni_from_clienthello_body() from the
 * app classifier. DPI_SKIP_REGISTER_ALL means this harness does NOT
 * need dpi_radius_parser.c, dpi_gtp_parser.c, or dpi_dns_parser.c at
 * all — it's genuinely QUIC-only now. See the guard's explanation in
 * dpi_dissector_registry.c. */
#include "dpi_app_classifier.c"
#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_quic_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 1500) return 0;   /* MAX_QUIC_PACKET bound in dpi_quic_parser.c */

    double confidence = quic_detect(Data, (uint16_t)Size, 443, "UDP");
    if (confidence <= 0.3) return 0;   /* mirrors dispatch_dissection()'s
                                          * MIN_DETECT_CONFIDENCE threshold */

    struct dissect_result out;
    quic_dissect(Data, (uint16_t)Size, 443, "UDP", &out);

    return 0;
}
