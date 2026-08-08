/*
 * fuzz_arp_parser.c
 *
 * libFuzzer harness for dpi_arp_parser.c. Plaintext, no crypto boundary.
 * Built to close a gap found during a later integration pass: this
 * dissector existed and was registered but had no fuzz harness yet,
 * unlike every other dissector in this project.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_arp_parser fuzz_arp_parser.c
 * Run:   ./fuzz_arp_parser fuzz_seeds/arp/ -max_len=64
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_arp_parser.c"

/* Resolves a real -Wunused-function warning a compiler caught:
 * arp_binding_reset_for_testing() existed (with its own clear
 * documented purpose) but was never actually called anywhere in this
 * project. Fixed by wiring it in at the one call site that actually
 * matches its documented intent — "between separate fuzzer
 * invocations" is exactly what LLVMFuzzerInitialize() is for: a
 * libFuzzer hook that runs once per process, before the first
 * LLVMFuzzerTestOneInput() call, never again after. This is
 * deliberately NOT the same fix as fuzz_tcp_reassembly.c's own
 * per-iteration reset (called at the end of every
 * LLVMFuzzerTestOneInput()) — copying that pattern here would undo
 * the exact thing this file's own comment below argues for: ARP's
 * binding-conflict check needs state to persist ACROSS iterations
 * within one run to ever be exercised at all, so a once-per-process
 * reset (clearing whatever a previous, unrelated process run might
 * have left behind, though C's zero-initialized statics mean this is
 * belt-and-suspenders in practice) is the right scope, not a
 * per-iteration one. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    arp_binding_reset_for_testing();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 64) return 0;

    double confidence = arp_detect(Data, (uint16_t)Size, 0, "ARP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    /* Deliberately NOT reset between iterations: the IP-MAC binding-
     * conflict check needs state to persist ACROSS calls to ever be
     * exercised at all (a conflict can only be detected on the second
     * packet for a given IP) — a libFuzzer persistent-mode run
     * naturally makes many calls in one process, letting the table
     * accumulate real cross-call state the same way it would in
     * actual use. `arp_binding_reset_for_testing()` exists for
     * between separate fuzzer invocations, not every iteration within
     * one — the table's own bounded size is what keeps a single
     * long-running campaign safe, not a reset. */
    arp_dissect(Data, (uint16_t)Size, 0, "ARP", &out);

    return 0;
}
