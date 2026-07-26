# tunneling/packet_utils.py
import struct


def checksum(data: bytes) -> int:
    """Checksum estándar de internet (RFC 1071), usado en headers IP e ICMP."""
    if len(data) % 2:
        data += b"\x00"

    total = sum(struct.unpack(f"!{len(data)//2}H", data))

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def _ip_to_bytes(ip_address: str) -> bytes:
    return bytes(int(o) for o in ip_address.split("."))


def build_icmp_echo_request(identifier: int, sequence: int, payload: bytes = b"PING-TEST") -> bytes:
    """Construye un paquete ICMP echo request (type=8) con checksum correcto."""
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    chk = checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, chk, identifier, sequence)
    return header + payload


def build_ipv4_packet(
    src_ip: str,
    dst_ip: str,
    payload: bytes,
    protocol: int = 1,
    ttl: int = 64,
    ident: int = 1,
) -> bytes:
    """Construye un paquete IPv4 crudo (header de 20 bytes, sin opciones) con checksum correcto."""
    version_ihl = (4 << 4) | 5
    total_length = 20 + len(payload)

    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length, ident, 0,
        ttl, protocol, 0,
        _ip_to_bytes(src_ip), _ip_to_bytes(dst_ip),
    )

    header_checksum = checksum(header_without_checksum)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length, ident, 0,
        ttl, protocol, header_checksum,
        _ip_to_bytes(src_ip), _ip_to_bytes(dst_ip),
    )

    return header + payload