"""
TriageForge Network Packet & PCAP Analyzer
Zero-dependency binary PCAP parser for identifying TCP retransmissions, resets,
SYN drops, and zero-window flow control stalls.
"""

from __future__ import annotations
import struct
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class PCAPAnalyzer:
    """Parses standard libpcap files and extracts transport-layer anomalies."""

    def analyze_file(self, pcap_path: str | Path) -> Dict[str, Any]:
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        raw_data = pcap_path.read_bytes()
        return self.analyze_bytes(raw_data)

    def analyze_bytes(self, raw_data: bytes) -> Dict[str, Any]:
        if len(raw_data) < 24:
            raise ValueError("Corrupt or incomplete PCAP header (< 24 bytes)")

        # Read 24-byte Global Header
        magic = struct.unpack("<I", raw_data[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            raise ValueError(f"Unrecognized PCAP magic number: {hex(magic)}")

        version_major, version_minor, thiszone, sigfigs, snaplen, link_type = struct.unpack(
            f"{endian}HHIIII", raw_data[4:24]
        )

        offset = 24
        total_packets = 0
        tcp_packets = 0
        syn_count = 0
        syn_ack_count = 0
        rst_count = 0
        retransmission_count = 0
        zero_window_count = 0

        # Flow tracking: (src_ip, src_port, dst_ip, dst_port) -> set(seq_numbers)
        seen_seqs: Dict[Tuple[str, int, str, int], set] = defaultdict(set)
        # SYN timestamps: (src_ip, src_port, dst_ip, dst_port) -> ts
        syn_timestamps: Dict[Tuple[str, int, str, int], float] = {}
        rtt_samples_ms: List[float] = []

        data_len = len(raw_data)

        while offset + 16 <= data_len:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", raw_data[offset : offset + 16])
            offset += 16

            if offset + incl_len > data_len:
                break

            packet = raw_data[offset : offset + incl_len]
            offset += incl_len
            total_packets += 1
            pkt_time = ts_sec + (ts_usec / 1_000_000.0)

            # Ethernet header (14 bytes) -> EtherType at offset 12
            if len(packet) < 14:
                continue
            eth_type = struct.unpack("!H", packet[12:14])[0]

            # IPv4 only (0x0800)
            if eth_type != 0x0800:
                continue

            ip_header = packet[14:]
            if len(ip_header) < 20:
                continue

            ihl = (ip_header[0] & 0x0F) * 4
            protocol = ip_header[9]

            # TCP only (Protocol 6)
            if protocol != 6:
                continue

            tcp_packets += 1
            src_ip = ".".join(str(b) for b in ip_header[12:16])
            dst_ip = ".".join(str(b) for b in ip_header[16:20])

            tcp_header = ip_header[ihl:]
            if len(tcp_header) < 20:
                continue

            src_port, dst_port, seq, ack, flags_raw, window_size = struct.unpack("!HHIIHH", tcp_header[:16])
            flags = flags_raw & 0x01FF

            is_syn = bool(flags & 0x0002)
            is_ack = bool(flags & 0x0010)
            is_rst = bool(flags & 0x0004)
            is_fin = bool(flags & 0x0001)

            flow_key = (src_ip, src_port, dst_ip, dst_port)
            reverse_flow = (dst_ip, dst_port, src_ip, src_port)

            # Analyze flags
            if is_rst:
                rst_count += 1

            if window_size == 0 and not is_rst:
                zero_window_count += 1

            if is_syn and not is_ack:
                syn_count += 1
                syn_timestamps[flow_key] = pkt_time
            elif is_syn and is_ack:
                syn_ack_count += 1
                if reverse_flow in syn_timestamps:
                    rtt = (pkt_time - syn_timestamps[reverse_flow]) * 1000.0
                    rtt_samples_ms.append(round(rtt, 2))

            # Detect TCP retransmissions (duplicate sequence numbers with payload)
            payload_len = len(tcp_header) - ((flags_raw >> 12) * 4)
            if payload_len > 0 or is_syn:
                if seq in seen_seqs[flow_key]:
                    retransmission_count += 1
                else:
                    seen_seqs[flow_key].add(seq)

        # Compute anomalies and assessment
        findings: List[str] = []
        if syn_count > 0 and syn_ack_count == 0:
            findings.append("CRITICAL: Outgoing TCP SYN packets received zero SYN-ACK responses. Indicative of firewall drop / Security Group block.")
        if rst_count > 0:
            findings.append(f"Identified {rst_count} TCP Reset (RST) packet(s). Port closed or connection forcefully terminated.")
        if retransmission_count > 0:
            retrans_rate = (retransmission_count / max(1, tcp_packets)) * 100.0
            findings.append(f"Detected {retransmission_count} retransmitted packet(s) ({retrans_rate:.1f}% retransmit rate). Indicates network congestion, packet loss, or MTU blackhole.")
        if zero_window_count > 0:
            findings.append(f"Detected {zero_window_count} TCP Zero-Window advertisement(s). Application receiver buffer is saturated.")

        avg_rtt = round(sum(rtt_samples_ms) / len(rtt_samples_ms), 2) if rtt_samples_ms else None

        return {
            "total_packets": total_packets,
            "tcp_packets": tcp_packets,
            "syn_count": syn_count,
            "syn_ack_count": syn_ack_count,
            "rst_count": rst_count,
            "retransmission_count": retransmission_count,
            "zero_window_count": zero_window_count,
            "avg_handshake_rtt_ms": avg_rtt,
            "findings": findings or ["No critical packet-level transport anomalies detected."],
        }
