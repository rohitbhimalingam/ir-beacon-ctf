#!/usr/bin/env python3
"""Recover the IR Beacon CTF flag from the staged loot ZIP."""

import argparse
import re
import struct
import zipfile
import zlib


def dns_exfil(pcap):
    magic = pcap[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported PCAP magic")

    offset = 24
    chunks = []
    while offset + 16 <= len(pcap):
        _, _, captured, _ = struct.unpack_from(endian + "IIII", pcap, offset)
        offset += 16
        packet = pcap[offset : offset + captured]
        offset += captured
        if len(packet) != captured or len(packet) < 42:
            continue

        ether_type = struct.unpack_from("!H", packet, 12)[0]
        ip_offset = 14
        if ether_type == 0x8100 and len(packet) >= 46:
            ether_type = struct.unpack_from("!H", packet, 16)[0]
            ip_offset = 18
        if ether_type != 0x0800 or packet[ip_offset] >> 4 != 4:
            continue
        ip_header_len = (packet[ip_offset] & 0x0F) * 4
        if packet[ip_offset + 9] != 17:
            continue

        udp_offset = ip_offset + ip_header_len
        dns_offset = udp_offset + 8
        if len(packet) < dns_offset + 13:
            continue
        dns = packet[dns_offset:]
        question_count = struct.unpack_from("!H", dns, 4)[0]
        if question_count == 0:
            continue

        pos = 12
        labels = []
        while pos < len(dns):
            size = dns[pos]
            pos += 1
            if size == 0:
                break
            if size & 0xC0 or pos + size > len(dns):
                labels = []
                break
            labels.append(dns[pos : pos + size].decode("ascii"))
            pos += size
        if len(labels) >= 3 and labels[-2:] == ["exfil", "lan"]:
            try:
                chunks.append((int(labels[1]), bytes.fromhex(labels[0])))
            except (ValueError, IndexError):
                continue

    if not chunks:
        raise ValueError("No exfiltration DNS queries found")
    return b"".join(data for _, data in sorted(chunks))


def png_lsb(png):
    if png[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Invalid PNG")
    offset = 8
    compressed = bytearray()
    width = height = bit_depth = color_type = None
    while offset + 12 <= len(png):
        size = struct.unpack_from(">I", png, offset)[0]
        kind = png[offset + 4 : offset + 8]
        data = png[offset + 8 : offset + 8 + size]
        offset += size + 12
        if kind == b"IHDR":
            width, height, bit_depth, color_type = struct.unpack_from(">IIBB", data)
        elif kind == b"IDAT":
            compressed.extend(data)
        elif kind == b"IEND":
            break

    if (bit_depth, color_type) != (8, 2):
        raise ValueError("Expected an 8-bit RGB PNG")
    raw = zlib.decompress(compressed)
    bpp = 3
    stride = width * bpp
    previous = bytearray(stride)
    pixels = bytearray()
    offset = 0

    for _ in range(height):
        filter_type = raw[offset]
        row = bytearray(raw[offset + 1 : offset + 1 + stride])
        offset += stride + 1
        for i in range(stride):
            left = row[i - bpp] if i >= bpp else 0
            above = previous[i]
            upper_left = previous[i - bpp] if i >= bpp else 0
            if filter_type == 1:
                row[i] = (row[i] + left) & 0xFF
            elif filter_type == 2:
                row[i] = (row[i] + above) & 0xFF
            elif filter_type == 3:
                row[i] = (row[i] + (left + above) // 2) & 0xFF
            elif filter_type == 4:
                estimate = left + above - upper_left
                distances = (
                    abs(estimate - left),
                    abs(estimate - above),
                    abs(estimate - upper_left),
                )
                predictor = (
                    left
                    if distances[0] <= distances[1] and distances[0] <= distances[2]
                    else above
                    if distances[1] <= distances[2]
                    else upper_left
                )
                row[i] = (row[i] + predictor) & 0xFF
            elif filter_type != 0:
                raise ValueError(f"Unsupported PNG filter: {filter_type}")
        pixels.extend(row)
        previous = row

    bits = "".join(str(channel & 1) for channel in pixels)
    return bytes(
        int(bits[i : i + 8], 2) for i in range(0, len(bits) - 7, 8)
    ).rstrip(b"\x00")


def cisco_type7(encoded):
    key = "dsfd;kfoA,.iyewrkldJKD"
    seed = int(encoded[:2], 10)
    ciphertext = bytes.fromhex(encoded[2:])
    return bytes(
        value ^ ord(key[(seed + i) % len(key)])
        for i, value in enumerate(ciphertext)
    )


def recover(zip_path):
    with zipfile.ZipFile(zip_path) as archive:
        pcap = archive.read("beacon_capture.pcap")
        image = archive.read("cam_backup.png")
        router = archive.read("rtr-config.txt").decode("ascii")

    dns_part = dns_exfil(pcap)
    image_part = png_lsb(image)
    match = re.search(r"password\s+7\s+([0-9A-Fa-f]+)", router)
    if not match:
        raise ValueError("Cisco type-7 password not found")
    router_part = cisco_type7(match.group(1))
    return dns_part + image_part + router_part


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("loot_zip", help="path to the staged loot ZIP")
    args = parser.parse_args()
    flag = recover(args.loot_zip).decode("ascii")
    print(flag)


if __name__ == "__main__":
    main()
