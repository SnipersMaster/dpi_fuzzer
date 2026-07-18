/*
 * fuzz_quic_frames.c
 *
 * libFuzzer harness for dpi_quic_parser.c's quic_process_decrypted_
 * payload() — the frame-type dispatch, CRYPTO frame extraction, and
 * SNI-parsing logic that only runs after successful AEAD decryption
 * in the real pipeline.
 *
 * THIS IS THE HARNESS THAT ACTUALLY MATTERS MOST for this file's
 * attacker-reachable surface. QUIC's Initial packets ARE
 * cryptographically protected, but with a publicly-known salt (RFC
 * 9001 S5.2, by design — that's what lets network observers see the
 * handshake at all). An attacker who wants to reach this code doesn't
 * need to break AES-GCM; they can legitimately construct arbitrary,
 * validly-encrypted Initial packets using the same public key
 * derivation this parser uses, then put ANY plaintext frame content
 * they want inside. So the plaintext this function processes is
 * exactly as attacker-controlled as raw bytes on the wire would be —
 * fuzzing it directly with raw mutator-generated input, bypassing the
 * AEAD step entirely, is not a shortcut that misses real attack
 * surface. It IS the real attack surface, just tested more directly
 * and far more efficiently than fighting through AES-GCM
 * authentication on every single mutated test case would allow.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_quic_frames fuzz_quic_frames.c -lssl -lcrypto
 * Run:   ./fuzz_quic_frames fuzz_seeds/quic_frames/ -max_len=4096
 *
 * NOT RUN in this environment — reviewed but not executed.
 */

#include <stdint.h>
#include <stddef.h>

#include "dpi_app_classifier.c"
#include "dpi_dissector_registry.c"
#include "dpi_radius_parser.c"
#include "dpi_quic_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0 || Size > MAX_QUIC_PACKET) return 0;

    struct dissect_result out;
    /* dissect_result_add() only appends fields, doesn't read
     * uninitialized state, but zeroing is cheap and removes any
     * dependency on that being true — don't rely on callee discipline
     * a fuzz harness doesn't need to assume. */
    __builtin_memset(&out, 0, sizeof(out));

    quic_process_decrypted_payload(Data, (int)Size, &out);

    return 0;
}
