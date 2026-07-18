#!/bin/bash
#
# fuzz_build.sh — build all five fuzz harnesses for this project.
#
# NOT RUN in this environment: no clang/libFuzzer toolchain is
# available in the sandbox this was written in (confirmed — `which
# clang` returns nothing). This script has been reviewed for
# correctness but not executed. Run it in your lab and fix whatever
# the compiler catches that a read-through couldn't, same caveat as
# every other piece of this project.
#
# Prerequisites:
#   sudo apt install clang libssl-dev
#   (AFL++ instead of libFuzzer: sudo apt install afl++, or build from
#    https://github.com/AFLplusplus/AFLplusplus)
#
set -euo pipefail

CFLAGS_COMMON="-g -O1 -fsanitize=fuzzer,address,undefined"
# -fsanitize=fuzzer     : libFuzzer engine + coverage instrumentation
# -fsanitize=address    : catches OOB reads/writes, use-after-free
# -fsanitize=undefined  : catches signed overflow, misaligned access,
#                         and other UB the parsers could hit on
#                         attacker-controlled length fields

echo "Building fuzz_rfc_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_rfc_parser fuzz_rfc_parser.c

echo "Building fuzz_tcp_reassembly (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_tcp_reassembly fuzz_tcp_reassembly.c

echo "Building fuzz_radius_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_radius_parser fuzz_radius_parser.c

echo "Building fuzz_gtp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_gtp_parser fuzz_gtp_parser.c

echo "Building fuzz_dns_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_dns_parser fuzz_dns_parser.c

echo "Building fuzz_ipv6_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ipv6_parser fuzz_ipv6_parser.c

echo "Building fuzz_http1_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_http1_parser fuzz_http1_parser.c

echo "Building fuzz_http2_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_http2_parser fuzz_http2_parser.c

echo "Building fuzz_ssh_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ssh_parser fuzz_ssh_parser.c

echo "Building fuzz_dhcp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_dhcp_parser fuzz_dhcp_parser.c

echo "Building fuzz_sip_rtp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_sip_rtp_parser fuzz_sip_rtp_parser.c

echo "Building fuzz_quic_header (needs OpenSSL)..."
clang $CFLAGS_COMMON -o fuzz_quic_header fuzz_quic_header.c -lssl -lcrypto

echo "Building fuzz_quic_frames (needs OpenSSL, but never calls into it —
      linked in only because dpi_quic_parser.c is compiled into this TU)..."
clang $CFLAGS_COMMON -o fuzz_quic_frames fuzz_quic_frames.c -lssl -lcrypto

echo ""
echo "Build complete. Run each against its seed corpus, e.g.:"
echo "  ./fuzz_rfc_parser fuzz_seeds/rfc_parser/ -max_len=2048"
echo "  ./fuzz_tcp_reassembly fuzz_seeds/tcp_reassembly/ -max_len=4096"
echo "  ./fuzz_radius_parser fuzz_seeds/radius/ -max_len=4096"
echo "  ./fuzz_gtp_parser fuzz_seeds/gtp/ -max_len=1500"
echo "  ./fuzz_dns_parser fuzz_seeds/dns/ -max_len=512"
echo "  ./fuzz_ipv6_parser fuzz_seeds/ipv6/ -max_len=1500"
echo "  ./fuzz_http1_parser fuzz_seeds/http1/ -max_len=4096"
echo "  ./fuzz_http2_parser fuzz_seeds/http2/ -max_len=4096"
echo "  ./fuzz_ssh_parser fuzz_seeds/ssh/ -max_len=2048"
echo "  ./fuzz_dhcp_parser fuzz_seeds/dhcp/ -max_len=1024"
echo "  ./fuzz_sip_rtp_parser fuzz_seeds/sip_rtp/ -max_len=2048"
echo "  ./fuzz_quic_header fuzz_seeds/quic_header/ -max_len=1500"
echo "  ./fuzz_quic_frames fuzz_seeds/quic_frames/ -max_len=4096"
echo ""
echo "Each will run indefinitely until stopped (Ctrl-C) or a crash is found."
echo "See FUZZING.md for how long to run, how to read the output, and how"
echo "to triage a crash."

#
# ---------------------------------------------------------------------
# AFL++ ALTERNATIVE (if you prefer AFL++ over libFuzzer):
# ---------------------------------------------------------------------
# AFL++ needs a slightly different harness shape — a main() reading
# from stdin or argv[1] instead of LLVMFuzzerTestOneInput. The simplest
# path that reuses these exact harness files: build with AFL++'s
# libFuzzer-compatible driver, which lets the SAME LLVMFuzzerTestOneInput
# function be driven by AFL++ instead of libFuzzer's own engine:
#
#   afl-clang-fast -g -O1 -fsanitize=address,undefined \
#       -o fuzz_rfc_parser_afl fuzz_rfc_parser.c \
#       $(afl-config --cflags --libs 2>/dev/null || echo "-lFuzzingEngine")
#
# Consult your AFL++ installation's docs for the exact driver library
# name/path — it varies by distribution/version. The harness .c files
# themselves do not need to change either way.
#
