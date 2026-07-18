# Fuzzing this DPI engine

Five libFuzzer harnesses, one seed corpus directory per harness. **None
of this has been compiled or run** — no clang/libFuzzer toolchain is
available in the sandbox these were written in (confirmed: `which
clang` returns nothing). Everything below is reviewed for correctness,
not executed. Run `fuzz_build.sh` in your lab, fix whatever the
compiler catches, then actually run these before trusting the parsers
on real traffic — that's the whole point of this exercise, and no
amount of code review substitutes for it.

## The five harnesses, and why there are five, not three

| Harness | Target | Crypto boundary? |
|---|---|---|
| `fuzz_rfc_parser.c` | IPv4 → TCP/UDP chain (`dpi_rfc_parser.c`) | None — plaintext |
| `fuzz_tcp_reassembly.c` | TCP flow reassembly, overlap policy (`dpi_tcp_flow_reassembly.c`) | None — plaintext, but **stateful** |
| `fuzz_radius_parser.c` | RADIUS attribute parsing (`dpi_radius_parser.c`) | None — plaintext |
| `fuzz_gtp_parser.c` | GTP-U v1 + GTPv2-C header/IE parsing (`dpi_gtp_parser.c`) | None — plaintext |
| `fuzz_dns_parser.c` | DNS header + question + answer/authority/additional parsing, especially name decompression (`dpi_dns_parser.c`) | None — plaintext, but the name-decompression logic is the highest-value target here given its history as a real-world bug source |
| `fuzz_ipv6_parser.c` | IPv6 header + extension header chain (`dpi_ipv6_parser.c`) | None — plaintext |
| `fuzz_http1_parser.c` | HTTP/1.1 request/status line + headers (`dpi_http1_parser.c`) | None — plaintext |
| `fuzz_http2_parser.c` | HTTP/2 frame parsing + HPACK-decoded headers (`dpi_http2_parser.c`) | None at the frame level; calls into the HPACK decoder below |
| `fuzz_hpack_decoder.c` | HPACK header block decoding directly (`dpi_hpack_decoder.c`) | None — plaintext, but this is the single most novel/least-precedented parsing logic in the project (257-entry Huffman table, dynamic table insertion/eviction) — **prioritize this one** |
| `fuzz_ssh_parser.c` | SSH banner + KEXINIT namelist parsing (`dpi_ssh_parser.c`) | None — plaintext (sent before encryption begins) |
| `fuzz_dhcp_parser.c` | DHCP TLV options (`dpi_dhcp_parser.c`) | None — plaintext |
| `fuzz_sip_rtp_parser.c` | SIP text parsing + RTP fixed header (`dpi_sip_rtp_parser.c`) | None — plaintext |
| `fuzz_quic_header.c` | QUIC pre-decryption parsing (`dpi_quic_parser.c`) | Yes — see below |
| `fuzz_quic_frames.c` | QUIC post-decryption frame walking + SNI (`dpi_quic_parser.c`) | Yes — see below |

**Note on single-dissector isolation**: `dpi_dissector_registry.c`'s
`register_all_dissectors()` references every protocol module's
registration function, which would otherwise force even a RADIUS-only
harness to link against QUIC/OpenSSL, GTP, and DNS just to satisfy
unused extern references. Each of these harnesses defines
`DPI_SKIP_REGISTER_ALL` before including the registry to avoid that —
see the guard's comment in `dpi_dissector_registry.c` for the full
explanation. This was a real coupling bug caught while adding the GTP
and DNS harnesses, not a design that was planned this way from the
start.

Four of these are ordinary raw-byte fuzzing targets: IPv4/TCP/UDP,
RADIUS, GTP-U/GTPv2-C, and DNS are all plaintext on the wire, so
there's nothing to work around. TCP flow reassembly is also plaintext,
but stateful — see its own section below for why that changes the
harness design.

**QUIC needed two harnesses because of its crypto boundary, and this
matters enough to explain properly, not just assert.** QUIC's Initial
packets are encrypted, but with a key derived from a publicly-known
salt (RFC 9001 §5.2) specifically so network observers *can* see the
handshake — this is a deliberate, documented property of the protocol,
not a weakness. That has a direct consequence for fuzzing: an attacker
constructing a malicious QUIC packet doesn't need to break AES-GCM —
they legitimately derive the same keys this parser does and encrypt
whatever plaintext they want. So the *plaintext* is exactly as
attacker-controlled as any other protocol's raw bytes, even though the
*wire bytes* are ciphertext.

If you fuzzed the whole pipeline with raw random bytes, though, nearly
every mutated test case would fail AES-GCM's authentication check and
never reach the frame-parsing logic at all — you'd be fuzzing the
"does this look structurally like a QUIC packet" logic thoroughly and
the actual frame/SNI parsing almost never. That's why this project
splits at the boundary:

- `fuzz_quic_header.c` fuzzes everything genuinely gated by the crypto
  check: varint decoding for connection ID/token/length fields, header
  protection removal, AAD/nonce construction. All of this runs on
  every input regardless of whether decryption ultimately succeeds — a
  bug in, say, computing the ciphertext/tag offsets before calling
  `aes_gcm_decrypt()` is exactly the kind of thing this harness can
  still catch even though decryption itself fails on nearly all random
  input.
- `fuzz_quic_frames.c` fuzzes `quic_process_decrypted_payload()`
  directly, treating the fuzz input as if it were already-decrypted
  plaintext. This is the harness that actually reaches frame-type
  dispatch, CRYPTO frame parsing, and the ClientHello/SNI extraction —
  the real attacker-reachable surface — without wasting nearly all of
  the fuzzer's time failing an auth check first.

This is a standard, well-established fuzzing technique for anything
with a crypto layer over attacker-reachable structure (compression,
authenticated tunneling protocols, etc.) — split the harness at the
trust boundary, don't make the fuzzer re-derive valid encryption on
every mutation just to reach the code you actually care about.

## The TCP reassembly harness is stateful — and this matters for its seeds

Unlike the others, `fuzz_tcp_reassembly.c` doesn't test one call in
isolation — the overlap-resolution and evasion-detection logic only
means anything across a *sequence* of segments with deliberately
varying seq/length/content relationships. The harness derives such a
sequence from the fuzz input (see the format documented in the file's
header) rather than fuzzing a single insert call, and resets its
dedicated flow-table partition after every run so state doesn't leak
between libFuzzer iterations — otherwise a long run would eventually
exhaust the bounded flow table and start silently skipping every
subsequent test case rather than exercising fresh state each time.

The three seeds provided are chosen to represent the three cases that
actually matter, not just "some traffic": in-order delivery, benign
identical-byte retransmission overlap, and conflicting-byte overlap
(the actual evasion-relevant case). A mutator starting from these three
is far more likely to explore interesting overlap combinations than one
starting from nothing.

## How long to run, and what "done" looks like

There's no universal answer, but rough guidance:

- **First pass**: run each harness for a few CPU-hours minimum before
  concluding anything. Crashes found in the first few minutes usually
  indicate something structurally wrong (a seed corpus issue, a build
  flag problem) rather than a subtle bug — investigate those first.
- **Coverage plateau**: libFuzzer prints coverage stats (`cov:`) as it
  runs. When coverage stops increasing for an extended period despite
  continued execution, you've likely exhausted what that harness alone
  can find — that's a reasonable point to consider a pass "complete"
  for now, not evidence of correctness.
- **`dpi_rfc_parser.c` and `dpi_quic_header.c`/`dpi_quic_frames.c`
  deserve the most CPU-time** of the five, per the original request
  here — they parse the most attacker-influenced structure (arbitrary
  network input, arbitrary QUIC frame content) with the least amount
  of protocol-level validation an attacker has to work around first.
- This is genuinely open-ended — continuous fuzzing (running these in
  CI indefinitely, or on a dedicated fuzzing server) catches
  regressions introduced by future changes, not just bugs present
  today. Treat "run it once for a few hours" as a floor, not a target.

## Triaging a crash

1. **Reproduce it directly**: libFuzzer saves crashing inputs to files
   (e.g. `crash-<hash>`) in the current directory. Re-run the harness
   binary directly on that file — it should crash deterministically:
   `./fuzz_rfc_parser crash-abc123`
2. **Get the ASan/UBSan report**: the crash output includes a stack
   trace and a description of what went wrong (buffer overflow,
   use-after-free, signed integer overflow, etc.) — this usually
   points directly at the offending line.
3. **Minimize the input**: libFuzzer can shrink a crashing input to the
   smallest one that still reproduces the bug, which makes root-causing
   much faster: `./fuzz_rfc_parser -minimize_crash=1 crash-abc123`
4. **Fix the actual bug, not just the symptom** — if it's a missing
   bounds check, add it with the same "check length before reading, not
   after" discipline used throughout this project. Don't just clamp the
   value and continue; that's the exact pattern this project has
   avoided everywhere else (reject and drop, don't guess).
5. **Add the (minimized) crashing input to the seed corpus permanently**
   as a regression test — copy it into `fuzz_seeds/<target>/` so future
   fuzzing runs and CI always re-check it, not just this one session.
6. **Re-run the full corpus** after the fix to confirm nothing else
   regressed and coverage didn't drop.

## What this does NOT replace

Fuzzing finds memory-safety and crash bugs. It does not verify
protocol *correctness* (e.g. that the QUIC key derivation actually
matches RFC 9001's test vectors — see the README's separate item on
that) or that the DGA/VPN scoring heuristics are well-calibrated. Those
need their own validation, already tracked separately in the README's
next-steps list.
