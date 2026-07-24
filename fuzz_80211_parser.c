/*
 * fuzz_80211_parser.c
 *
 * libFuzzer harness for dpi_80211_parser.c. This dissector isn't
 * reached through `dispatch_dissection()` FROM the main capture path
 * (802.11 is a link layer, not a TCP/UDP/IP-protocol-dispatched
 * protocol, and this file isn't wired into `register_all_dissectors()`
 * — see its own header comment) — but it DOES call
 * `dispatch_dissection()` INTERNALLY now, for Data frames carrying
 * SNAP-encapsulated ARP or IPv4-then-TCP-then-HTTP traffic. Both
 * corrections matter for this harness specifically:
 *
 *   1. A REAL GAP IN THIS HARNESS FOUND AND FIXED: with
 *      `DPI_SKIP_REGISTER_ALL` defined and nothing explicitly
 *      registered, `dispatch_dissection()` always found zero
 *      candidate dissectors and returned false — meaning every real
 *      ARP/HTTP-shaped seed in this corpus was only ever exercising
 *      the "no match" fallback path, never the actual field-
 *      extraction code inside `dot11_dissect_data()`. Fixed by
 *      explicitly registering just ARP and HTTP/1.1 (not the full
 *      `register_all_dissectors()`, keeping this harness focused on
 *      what `dot11_dissect_data()` actually recurses into).
 *   2. max_len raised from 512 to 2312 (IEEE 802.11's actual maximum
 *      MSDU size) — the previous limit silently rejected real,
 *      legitimately-sized Data frames carrying bridged Ethernet/IP
 *      traffic (a real captured HTTP request used for a new seed is
 *      1,540 bytes, comfortably over the old 512-byte cap).
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_80211_parser fuzz_80211_parser.c
 * Run:   ./fuzz_80211_parser fuzz_seeds/80211/ -max_len=2312
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_rfc_parser.c"
#include "dpi_arp_parser.c"
#include "dpi_http1_parser.c"
#include "dpi_80211_parser.c"

static int g_registered = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 2312) return 0;

    if (!g_registered) {
        register_arp_dissector();
        register_http1_dissector();
        g_registered = 1;
    }

    struct dissect_result out;
    dot11_dissect_frame(Data, Size, &out);

    return 0;
}
