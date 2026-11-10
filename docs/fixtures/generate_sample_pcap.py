"""
Generates a realistic sample PCAP file with TCP SYN retransmissions and RST packets.
"""

import struct
from pathlib import Path


def generate_sample_pcap(out_path: Path):
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    packets = []
    # Packet 1: Outgoing SYN from 198.51.100.10:49812 -> 10.0.1.15:443 (Seq: 1000)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip1 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 101, 0, 64, 6, 0, bytes([198, 51, 100, 10]), bytes([10, 0, 1, 15]))
    tcp1 = struct.pack("!HHIIHHHH", 49812, 443, 1000, 0, 0x5002, 64240, 0, 0) # SYN
    pkt1 = eth + ip1 + tcp1
    packets.append((1700140000, 100000, pkt1))

    # Packet 2: Retransmitted SYN (1 second later, same Seq: 1000)
    packets.append((1700140001, 105000, pkt1))

    # Packet 3: Retransmitted SYN (3 seconds later, same Seq: 1000)
    packets.append((1700140003, 110000, pkt1))

    # Packet 4: TCP RST from 10.0.1.15:80 -> 198.51.100.10:51234
    ip2 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 202, 0, 64, 6, 0, bytes([10, 0, 1, 15]), bytes([198, 51, 100, 10]))
    tcp2 = struct.pack("!HHIIHHHH", 80, 51234, 0, 500, 0x5004, 0, 0, 0) # RST
    pkt2 = eth + ip2 + tcp2
    packets.append((1700140004, 200000, pkt2))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(global_hdr)
        for ts_sec, ts_usec, pkt in packets:
            rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
            f.write(rec_hdr)
            f.write(pkt)

    print(f"Generated sample PCAP: {out_path}")


if __name__ == "__main__":
    generate_sample_pcap(Path(__file__).resolve().parent / "sample_traffic.pcap")
