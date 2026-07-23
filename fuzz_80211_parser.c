/*
 * fuzz_80211_parser.c
 *
 * libFuzzer harness for dpi_80211_parser.c. This dissector isn't
 * reached through `dispatch_dissection()` at runtime (802.11 is a
 * link layer, not a TCP/UDP/IP-protocol-dispatched protocol, and this
 * file isn't wired into `register_all_dissectors()` — see its own
 * header comment) — but it still uses the same `dissect_result`
 * API/struct as every other dissector in this project, so this
 * harness pulls in the real registry file for that struct/function
 * definition, same as every other fuzz harness here, rather than
 * inventing a parallel stand-in.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_80211_parser fuzz_80211_parser.c
 * Run:   ./fuzz_80211_parser fuzz_seeds/80211/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_80211_parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    struct dissect_result out;
    dot11_dissect_frame(Data, Size, &out);

    return 0;
}
