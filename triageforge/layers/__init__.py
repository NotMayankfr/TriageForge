"""
Diagnostic Layers for TriageForge
Each layer inspects a specific tier of the network and application stack:
- DNS Layer: name resolution, latency, resolver failures
- TCP Layer: socket connectivity, timeout vs connection refused
- TLS Layer: certificate validity, expiry, SAN names, chain
- HTTP Layer: latency breakdown (DNS, TCP, TLS, TTFB), status code, headers, error body signatures
- Host Layer: container status, system metrics, disk & inodes, memory & OOM, database connections
"""

from triageforge.layers.dns_layer import DNSLayer
from triageforge.layers.tcp_layer import TCPLayer
from triageforge.layers.tls_layer import TLSLayer
from triageforge.layers.http_layer import HTTPLayer
from triageforge.layers.host_layer import HostLayer

__all__ = ["DNSLayer", "TCPLayer", "TLSLayer", "HTTPLayer", "HostLayer"]
