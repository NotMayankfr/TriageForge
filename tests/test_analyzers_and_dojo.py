"""
Unit tests for TriageForge advanced features: PCAPAnalyzer, LogAnalyzer, and DojoManager.
"""

import struct
from pathlib import Path
import pytest
from triageforge.analyzer.log_analyzer import LogAnalyzer
from triageforge.analyzer.pcap_analyzer import PCAPAnalyzer
from triageforge.dojo import DojoManager, SCENARIOS


def test_log_analyzer_vpc_flow():
    analyzer = LogAnalyzer()
    sample_flow = """version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log_status
2 123456789012 eni-abc 198.51.100.4 10.0.1.15 49152 443 6 5 260 1620140000 1620140060 REJECT OK
2 123456789012 eni-abc 198.51.100.4 10.0.1.15 49154 443 6 3 156 1620140000 1620140060 REJECT OK
2 123456789012 eni-abc 10.0.1.5 10.0.1.15 50000 80 6 12 1200 1620140000 1620140060 ACCEPT OK
"""
    res = analyzer.analyze_vpc_flow_logs(sample_flow)
    assert res["total_flows"] == 3
    assert res["rejected_flows"] == 2
    assert res["accepted_flows"] == 1
    assert "443" in res["top_rejected_ports"]
    assert len(res["findings"]) > 0
    assert "dropped 2 flow(s)" in res["findings"][0]


def test_log_analyzer_nginx():
    analyzer = LogAnalyzer()
    sample_nginx = """172.18.0.1 - - [10/Nov/2024:14:20:00 +0000] "GET /health HTTP/1.1" 200 15
172.18.0.1 - - [10/Nov/2024:14:22:45 +0000] "GET /api/items HTTP/1.1" 502 157
172.18.0.1 - - [10/Nov/2024:14:22:48 +0000] "GET /api/items HTTP/1.1" 502 157
172.18.0.1 - - [10/Nov/2024:14:23:00 +0000] "GET /api/users HTTP/1.1" 404 42
"""
    res = analyzer.analyze_nginx_logs(sample_nginx)
    assert res["total_requests"] == 4
    assert res["2xx_success"] == 1
    assert res["5xx_server_errors"] == 2
    assert res["4xx_client_errors"] == 1
    assert res["error_rate_5xx_pct"] == 50.0
    assert "/api/items" in res["failing_endpoints"]


def test_pcap_analyzer_synthetic_syn_drop():
    """Builds a minimal synthetic PCAP buffer in memory to test parsing logic."""
    analyzer = PCAPAnalyzer()

    # 1. PCAP 24-byte Global Header (Standard little-endian)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # 2. Ethernet Header (14 bytes): Dst MAC, Src MAC, EtherType 0x0800
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

    # 3. IPv4 Header (20 bytes): protocol 6 (TCP), src 10.0.0.1, dst 10.0.0.2
    # version=4, ihl=5 -> 0x45
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))

    # 4. TCP Header (20 bytes): src_port 51234, dst_port 443, seq 100, ack 0, flags 0x0002 (SYN), win 64240
    # data_offset 5 -> (5 << 12) | 0x0002 = 0x5002
    tcp_hdr = struct.pack("!HHIIHHHH", 51234, 443, 100, 0, 0x5002, 64240, 0, 0)

    packet_bytes = eth_hdr + ip_hdr + tcp_hdr
    pkt_len = len(packet_bytes)

    # Packet Record Header (16 bytes)
    rec_hdr = struct.pack("<IIII", 1620140000, 100000, pkt_len, pkt_len)

    raw_pcap = global_hdr + rec_hdr + packet_bytes

    res = analyzer.analyze_bytes(raw_pcap)
    assert res["total_packets"] == 1
    assert res["tcp_packets"] == 1
    assert res["syn_count"] == 1
    assert res["syn_ack_count"] == 0
    assert any("SYN packets received zero SYN-ACK responses" in f for f in res["findings"])


def test_dojo_scenario_catalog():
    assert len(SCENARIOS) == 10
    for fid, sc in SCENARIOS.items():
        assert "title" in sc
        assert "severity" in sc
        assert "customer_report" in sc
        assert len(sc["hints"]) == 3
