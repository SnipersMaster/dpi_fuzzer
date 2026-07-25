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

echo "Building fuzz_hpack_decoder (no crypto deps - highest priority of the new harnesses)..."
clang $CFLAGS_COMMON -o fuzz_hpack_decoder fuzz_hpack_decoder.c

echo "Building fuzz_icmp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_icmp_parser fuzz_icmp_parser.c

echo "Building fuzz_arp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_arp_parser fuzz_arp_parser.c

echo "Building fuzz_mqtt_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_mqtt_parser fuzz_mqtt_parser.c

echo "Building fuzz_ntp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ntp_parser fuzz_ntp_parser.c

echo "Building fuzz_snmp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_snmp_parser fuzz_snmp_parser.c

echo "Building fuzz_stun_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_stun_parser fuzz_stun_parser.c

echo "Building fuzz_modbus_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_modbus_parser fuzz_modbus_parser.c

echo "Building fuzz_dnp3_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_dnp3_parser fuzz_dnp3_parser.c

echo "Building fuzz_vlan_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_vlan_parser fuzz_vlan_parser.c

echo "Building fuzz_gre_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_gre_parser fuzz_gre_parser.c

echo "Building fuzz_mpls_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_mpls_parser fuzz_mpls_parser.c

echo "Building fuzz_ospf_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ospf_parser fuzz_ospf_parser.c

echo "Building fuzz_bgp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_bgp_parser fuzz_bgp_parser.c

echo "Building fuzz_ldap_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ldap_parser fuzz_ldap_parser.c

echo "Building fuzz_ftp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ftp_parser fuzz_ftp_parser.c

echo "Building fuzz_igmp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_igmp_parser fuzz_igmp_parser.c

echo "Building fuzz_rip_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_rip_parser fuzz_rip_parser.c

echo "Building fuzz_ssdp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ssdp_parser fuzz_ssdp_parser.c

echo "Building fuzz_syslog_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_syslog_parser fuzz_syslog_parser.c

echo "Building fuzz_mdns_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_mdns_parser fuzz_mdns_parser.c

echo "Building fuzz_esp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_esp_parser fuzz_esp_parser.c

echo "Building fuzz_hsrp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_hsrp_parser fuzz_hsrp_parser.c

echo "Building fuzz_6in4_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_6in4_parser fuzz_6in4_parser.c

echo "Building fuzz_isakmp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_isakmp_parser fuzz_isakmp_parser.c

echo "Building fuzz_ldp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ldp_parser fuzz_ldp_parser.c

echo "Building fuzz_eigrp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_eigrp_parser fuzz_eigrp_parser.c

echo "Building fuzz_s7comm_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_s7comm_parser fuzz_s7comm_parser.c

echo "Building fuzz_telnet_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_telnet_parser fuzz_telnet_parser.c

echo "Building fuzz_ah_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ah_parser fuzz_ah_parser.c

echo "Building fuzz_netbios_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_netbios_parser fuzz_netbios_parser.c

echo "Building fuzz_pop3_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_pop3_parser fuzz_pop3_parser.c

echo "Building fuzz_msnp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_msnp_parser fuzz_msnp_parser.c

echo "Building fuzz_smb1_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_smb1_parser fuzz_smb1_parser.c

echo "Building fuzz_lldp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_lldp_parser fuzz_lldp_parser.c

echo "Building fuzz_kerberos_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_kerberos_parser fuzz_kerberos_parser.c

echo "Building fuzz_l2tpv3_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_l2tpv3_parser fuzz_l2tpv3_parser.c

echo "Building fuzz_whois_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_whois_parser fuzz_whois_parser.c

echo "Building fuzz_tftp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_tftp_parser fuzz_tftp_parser.c

echo "Building fuzz_wol_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_wol_parser fuzz_wol_parser.c

echo "Building fuzz_wow_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_wow_parser fuzz_wow_parser.c

echo "Building fuzz_bt_dht_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_bt_dht_parser fuzz_bt_dht_parser.c

echo "Building fuzz_sctp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_sctp_parser fuzz_sctp_parser.c

echo "Building fuzz_m3ua_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_m3ua_parser fuzz_m3ua_parser.c

echo "Building fuzz_amqp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_amqp_parser fuzz_amqp_parser.c

echo "Building fuzz_stp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_stp_parser fuzz_stp_parser.c

echo "Building fuzz_m2ua_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_m2ua_parser fuzz_m2ua_parser.c

echo "Building fuzz_pim_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_pim_parser fuzz_pim_parser.c

echo "Building fuzz_appletalk_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_appletalk_parser fuzz_appletalk_parser.c

echo "Building fuzz_ipv4_fragmentation (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_ipv4_fragmentation fuzz_ipv4_fragmentation.c

echo "Building fuzz_http2_continuation_reassembly (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_http2_continuation_reassembly fuzz_http2_continuation_reassembly.c

echo "Building fuzz_80211_parser (standalone, not registry-wired — see file header)..."
clang $CFLAGS_COMMON -o fuzz_80211_parser fuzz_80211_parser.c

echo "Building fuzz_smtp_parser (no crypto deps)..."
clang $CFLAGS_COMMON -o fuzz_smtp_parser fuzz_smtp_parser.c

echo "Building fuzz_http2_continuation (dedicated CONTINUATION reassembly harness)..."
clang $CFLAGS_COMMON -o fuzz_http2_continuation fuzz_http2_continuation.c

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
echo "  ./fuzz_hpack_decoder fuzz_seeds/hpack/ -max_len=4096"
echo "  ./fuzz_icmp_parser fuzz_seeds/icmp/ -max_len=1500"
echo "  ./fuzz_arp_parser fuzz_seeds/arp/ -max_len=64"
echo "  ./fuzz_mqtt_parser fuzz_seeds/mqtt/ -max_len=2048"
echo "  ./fuzz_ntp_parser fuzz_seeds/ntp/ -max_len=128"
echo "  ./fuzz_snmp_parser fuzz_seeds/snmp/ -max_len=1024"
echo "  ./fuzz_stun_parser fuzz_seeds/stun/ -max_len=1024"
echo "  ./fuzz_modbus_parser fuzz_seeds/modbus/ -max_len=512"
echo "  ./fuzz_dnp3_parser fuzz_seeds/dnp3/ -max_len=300"
echo "  ./fuzz_vlan_parser fuzz_seeds/vlan/ -max_len=64"
echo "  ./fuzz_gre_parser fuzz_seeds/gre/ -max_len=1500"
echo "  ./fuzz_mpls_parser fuzz_seeds/mpls/ -max_len=1500"
echo "  ./fuzz_ospf_parser fuzz_seeds/ospf/ -max_len=1500"
echo "  ./fuzz_bgp_parser fuzz_seeds/bgp/ -max_len=2048"
echo "  ./fuzz_ldap_parser fuzz_seeds/ldap/ -max_len=2048"
echo "  ./fuzz_ftp_parser fuzz_seeds/ftp/ -max_len=1024"
echo "  ./fuzz_igmp_parser fuzz_seeds/igmp/ -max_len=256"
echo "  ./fuzz_rip_parser fuzz_seeds/rip/ -max_len=512"
echo "  ./fuzz_ssdp_parser fuzz_seeds/ssdp/ -max_len=1024"
echo "  ./fuzz_syslog_parser fuzz_seeds/syslog/ -max_len=1024"
echo "  ./fuzz_mdns_parser fuzz_seeds/mdns/ -max_len=1024"
echo "  ./fuzz_esp_parser fuzz_seeds/esp/ -max_len=64"
echo "  ./fuzz_hsrp_parser fuzz_seeds/hsrp/ -max_len=128"
echo "  ./fuzz_6in4_parser fuzz_seeds/6in4/ -max_len=512"
echo "  ./fuzz_isakmp_parser fuzz_seeds/isakmp/ -max_len=512"
echo "  ./fuzz_ldp_parser fuzz_seeds/ldp/ -max_len=1024"
echo "  ./fuzz_eigrp_parser fuzz_seeds/eigrp/ -max_len=512"
echo "  ./fuzz_s7comm_parser fuzz_seeds/s7comm/ -max_len=256"
echo "  ./fuzz_telnet_parser fuzz_seeds/telnet/ -max_len=512"
echo "  ./fuzz_ah_parser fuzz_seeds/ah/ -max_len=256"
echo "  ./fuzz_netbios_parser fuzz_seeds/netbios/ -max_len=512"
echo "  ./fuzz_pop3_parser fuzz_seeds/pop3/ -max_len=512"
echo "  ./fuzz_msnp_parser fuzz_seeds/msnp/ -max_len=512"
echo "  ./fuzz_smb1_parser fuzz_seeds/smb1/ -max_len=1024"
echo "  ./fuzz_lldp_parser fuzz_seeds/lldp/ -max_len=512"
echo "  ./fuzz_kerberos_parser fuzz_seeds/kerberos/ -max_len=512"
echo "  ./fuzz_l2tpv3_parser fuzz_seeds/l2tpv3/ -max_len=512"
echo "  ./fuzz_whois_parser fuzz_seeds/whois/ -max_len=512"
echo "  ./fuzz_tftp_parser fuzz_seeds/tftp/ -max_len=512"
echo "  ./fuzz_wol_parser fuzz_seeds/wol/ -max_len=256"
echo "  ./fuzz_wow_parser fuzz_seeds/wow/ -max_len=256"
echo "  ./fuzz_bt_dht_parser fuzz_seeds/bt_dht/ -max_len=512"
echo "  ./fuzz_sctp_parser fuzz_seeds/sctp/ -max_len=512"
echo "  ./fuzz_m3ua_parser fuzz_seeds/m3ua/ -max_len=256"
echo "  ./fuzz_amqp_parser fuzz_seeds/amqp/ -max_len=512"
echo "  ./fuzz_stp_parser fuzz_seeds/stp/ -max_len=128"
echo "  ./fuzz_m2ua_parser fuzz_seeds/m2ua/ -max_len=256"
echo "  ./fuzz_pim_parser fuzz_seeds/pim/ -max_len=256"
echo "  ./fuzz_appletalk_parser fuzz_seeds/appletalk/ -max_len=128"
echo "  ./fuzz_ipv4_fragmentation fuzz_seeds/ipv4_fragmentation/ -max_len=1500"
echo "  ./fuzz_http2_continuation_reassembly fuzz_seeds/http2_continuation_reassembly/ -max_len=4096"
echo "  ./fuzz_80211_parser fuzz_seeds/80211/ -max_len=2312"
echo "  ./fuzz_smtp_parser fuzz_seeds/smtp/ -max_len=2048"
echo "  ./fuzz_http2_continuation fuzz_seeds/http2_continuation/ -max_len=64"
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
