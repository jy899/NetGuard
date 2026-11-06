"""Cisco Packet Tracer project files (.pkt, .pka): decoding and reading the topology.

Packet Tracer 5 and later store the project XML compressed, obfuscated and encrypted with Twofish in EAX mode. The
format (and its fixed key and nonce) is documented by the open-source pka2xml project:

    1. reverse the bytes and XOR byte i with (length - i * length)
    2. Twofish-EAX decryption, key = 16 x 0x89, nonce = 16 x 0x10, the 16-byte tag at the end
    3. XOR byte i with (length - i)
    4. Qt qCompress: a 4-byte big-endian length, then a zlib stream

Twofish (Schneier et al., 1998) and EAX (Bellare, Rogaway and Wagner, 2004) are implemented here in pure Python and
checked against their published test vectors, so no extra dependency is needed on Windows.
"""
from __future__ import annotations

import re
import struct
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field

# ------------------------------------------------------------------ Twofish
_Q0_T = ([8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4], [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
         [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1], [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10])
_Q1_T = ([2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5], [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8],
         [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15], [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10])
_MDS = ((0x01, 0xEF, 0x5B, 0x5B), (0x5B, 0xEF, 0xEF, 0x01), (0xEF, 0x5B, 0x01, 0xEF), (0xEF, 0x01, 0xEF, 0x5B))
_RS = ((0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E), (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
       (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19), (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03))
_M32 = 0xFFFFFFFF


def _ror4(x, n):
    return ((x >> n) | (x << (4 - n))) & 0xF


def _q(t, x):
    a0, b0 = x >> 4, x & 0xF
    a1, b1 = a0 ^ b0, (a0 ^ _ror4(b0, 1) ^ (8 * a0)) & 0xF
    a2, b2 = t[0][a1], t[1][b1]
    a3, b3 = a2 ^ b2, (a2 ^ _ror4(b2, 1) ^ (8 * a2)) & 0xF
    return (t[3][b3] << 4) | t[2][a3]


Q0 = [_q(_Q0_T, x) for x in range(256)]
Q1 = [_q(_Q1_T, x) for x in range(256)]


def _gf(a, b, poly):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return result


_MDS_MUL = [[[_gf(_MDS[r][c], x, 0x169) for x in range(256)] for c in range(4)] for r in range(4)]


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def _ror(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


def _h(x: int, words: list[int]) -> int:
    y = [(x >> (8 * i)) & 0xFF for i in range(4)]
    b = [[(w >> (8 * i)) & 0xFF for i in range(4)] for w in words]
    k = len(words)
    if k == 4:
        y = [Q1[y[0]] ^ b[3][0], Q0[y[1]] ^ b[3][1], Q0[y[2]] ^ b[3][2], Q1[y[3]] ^ b[3][3]]
    if k >= 3:
        y = [Q1[y[0]] ^ b[2][0], Q1[y[1]] ^ b[2][1], Q0[y[2]] ^ b[2][2], Q0[y[3]] ^ b[2][3]]
    y = [Q1[Q0[Q0[y[0]] ^ b[1][0]] ^ b[0][0]], Q0[Q0[Q1[y[1]] ^ b[1][1]] ^ b[0][1]],
         Q1[Q1[Q0[y[2]] ^ b[1][2]] ^ b[0][2]], Q0[Q1[Q1[y[3]] ^ b[1][3]] ^ b[0][3]]]
    z = [_MDS_MUL[r][0][y[0]] ^ _MDS_MUL[r][1][y[1]] ^ _MDS_MUL[r][2][y[2]] ^ _MDS_MUL[r][3][y[3]] for r in range(4)]
    return z[0] | (z[1] << 8) | (z[2] << 16) | (z[3] << 24)


class Twofish:
    """Block cipher with 16-byte blocks and 128, 192 or 256-bit keys."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish keys are 16, 24 or 32 bytes")
        k = len(key) // 8
        words = list(struct.unpack(f"<{2 * k}I", key))
        even, odd = words[0::2], words[1::2]
        s = []
        for i in range(k):
            chunk = key[8 * i:8 * i + 8]
            v = [0, 0, 0, 0]
            for r in range(4):
                for c in range(8):
                    v[r] ^= _gf(_RS[r][c], chunk[c], 0x14D)
            s.append(v[0] | (v[1] << 8) | (v[2] << 16) | (v[3] << 24))
        self.s = list(reversed(s))
        self.k = []
        rho = 0x01010101
        for i in range(20):
            a = _h((2 * i * rho) & _M32, even)
            b = _rol(_h(((2 * i + 1) * rho) & _M32, odd), 8)
            self.k += [(a + b) & _M32, _rol((a + 2 * b) & _M32, 9)]

    def _g(self, x):
        return _h(x, self.s)

    def encrypt_block(self, block: bytes) -> bytes:
        r = list(struct.unpack("<4I", block))
        r = [r[i] ^ self.k[i] for i in range(4)]
        for rnd in range(16):
            t0, t1 = self._g(r[0]), self._g(_rol(r[1], 8))
            f0 = (t0 + t1 + self.k[2 * rnd + 8]) & _M32
            f1 = (t0 + 2 * t1 + self.k[2 * rnd + 9]) & _M32
            r2, r3 = _ror(r[2] ^ f0, 1), _rol(r[3], 1) ^ f1
            r = [r2, r3, r[0], r[1]]
        out = [r[2] ^ self.k[4], r[3] ^ self.k[5], r[0] ^ self.k[6], r[1] ^ self.k[7]]
        return struct.pack("<4I", *out)


# ------------------------------------------------------------------ EAX
def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _dbl(block: bytes) -> bytes:
    value = int.from_bytes(block, "big") << 1
    if value >> 128:
        value = (value ^ 0x87) & ((1 << 128) - 1)
    return value.to_bytes(16, "big")


class Eax:
    """EAX authenticated encryption over any 16-byte block cipher with an encrypt_block method."""

    def __init__(self, cipher):
        self.cipher = cipher
        k1 = _dbl(cipher.encrypt_block(bytes(16)))
        self.k1, self.k2 = k1, _dbl(k1)

    def _cmac(self, data: bytes) -> bytes:
        blocks = [data[i:i + 16] for i in range(0, len(data), 16)] or [b""]
        state = bytes(16)
        for block in blocks[:-1]:
            state = self.cipher.encrypt_block(_xor(state, block))
        last = blocks[-1]
        last = _xor(last, self.k1) if len(last) == 16 else _xor(last + b"\x80" + bytes(15 - len(last)), self.k2)
        return self.cipher.encrypt_block(_xor(state, last))

    def _omac(self, tag: int, data: bytes) -> bytes:
        return self._cmac(bytes(15) + bytes([tag]) + data)

    def _ctr(self, nonce_mac: bytes, data: bytes) -> bytes:
        counter, out = int.from_bytes(nonce_mac, "big"), bytearray()
        for i in range(0, len(data), 16):
            stream = self.cipher.encrypt_block(((counter + i // 16) % (1 << 128)).to_bytes(16, "big"))
            out += _xor(data[i:i + 16], stream)
        return bytes(out)

    def encrypt(self, nonce: bytes, plaintext: bytes, header: bytes = b"") -> tuple[bytes, bytes]:
        n = self._omac(0, nonce)
        ciphertext = self._ctr(n, plaintext)
        tag = _xor(_xor(n, self._omac(1, header)), self._omac(2, ciphertext))
        return ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, header: bytes = b"") -> bytes:
        n = self._omac(0, nonce)
        expected = _xor(_xor(n, self._omac(1, header)), self._omac(2, ciphertext))
        if expected[:len(tag)] != tag:
            raise ValueError("authentication tag mismatch")
        return self._ctr(n, ciphertext)


# ------------------------------------------------------------------ Packet Tracer file format
KEY, NONCE = bytes([0x89] * 16), bytes([0x10] * 16)


class PacketTracerError(Exception):
    pass


def decode(data: bytes) -> str:
    """The project XML of a .pkt/.pka file (or the XML itself, when Packet Tracer exported it decoded)."""
    head = data[:200].lstrip()
    if head.startswith(b"<"):
        return data.decode("utf-8", "replace")
    length = len(data)
    if length < 40:
        raise PacketTracerError("The file is too small to be a Packet Tracer project.")
    stage1 = bytes(data[length - 1 - i] ^ ((length - i * length) & 0xFF) for i in range(length))
    try:
        stage2 = Eax(Twofish(KEY)).decrypt(NONCE, stage1[:-16], stage1[-16:])
    except ValueError:
        raise PacketTracerError("This is not a Packet Tracer 5+ project file (or it is damaged).") from None
    stage3 = bytes(b ^ ((len(stage2) - i) & 0xFF) for i, b in enumerate(stage2))
    try:
        xml = zlib.decompress(stage3[4:])
    except zlib.error:
        raise PacketTracerError("The Packet Tracer project could not be decompressed.") from None
    return xml.decode("utf-8", "replace")


def encode(xml: str) -> bytes:
    """The inverse of decode (used by the tests to build project files)."""
    raw = xml.encode()
    stage3 = struct.pack(">I", len(raw)) + zlib.compress(raw)
    stage2 = bytes(b ^ ((len(stage3) - i) & 0xFF) for i, b in enumerate(stage3))
    ciphertext, tag = Eax(Twofish(KEY)).encrypt(NONCE, stage2)
    stage1 = ciphertext + tag
    length = len(stage1)
    out = bytearray(length)
    for i in range(length):
        out[length - 1 - i] = stage1[i] ^ ((length - i * length) & 0xFF)
    return bytes(out)


# ------------------------------------------------------------------ topology
@dataclass
class PtDevice:
    ref: str
    name: str
    kind: str            # router | switch | firewall | pc | server | internet
    model: str | None
    config: str | None   # running (or startup) configuration
    ip: str | None = None
    mask: str | None = None
    gateway: str | None = None
    nic: str | None = None
    x: float | None = None
    y: float | None = None
    routing: bool = False


@dataclass
class PtTopology:
    name: str
    devices: list[PtDevice]
    links: list[tuple[str, str | None, str, str | None]]   # (device ref, port, device ref, port)
    flows: list[tuple[str, str, str]] = field(default_factory=list)  # (source ref, destination ref, protocol)
    version: str | None = None


_KIND = {"router": "router", "switch": "switch", "multilayerswitch": "switch", "pc": "pc", "laptop": "pc",
         "tablet": "pc", "pda": "pc", "smartphone": "pc", "server": "server", "printer": "server", "cloud": "internet",
         "dslmodem": "internet", "cablemodem": "internet", "asa": "firewall", "firewall": "firewall",
         "wirelessrouter": "router", "homerouter": "router", "hub": "switch", "bridge": "switch",
         "accesspoint": "switch", "ipphone": "pc"}


def _text(node, path):
    found = node.find(path)
    return found.text.strip() if found is not None and found.text else None


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse(xml: str, fallback_name: str = "Packet Tracer project") -> PtTopology:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise PacketTracerError(f"The Packet Tracer project XML could not be read ({exc}).") from None
    devices: list[PtDevice] = []
    refs: dict[str, PtDevice] = {}
    for index, node in enumerate(root.iter("DEVICE")):
        engine = node.find("ENGINE")
        if engine is None:
            continue
        type_node = engine.find("TYPE")
        raw_type = (type_node.text or "").strip() if type_node is not None else ""
        model = type_node.get("model") if type_node is not None else None
        kind = _KIND.get(re.sub(r"[^a-z]", "", raw_type.lower()), "router")
        name = _text(engine, "NAME") or f"{raw_type or 'Device'}{index}"
        config = None
        for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            section = engine.find(tag)
            if section is not None and section.findall("LINE"):
                config = "\n".join((line.text or "") for line in section.findall("LINE"))
                break
        ip = mask = None
        for port in engine.iter("PORT"):
            if _text(port, "IP"):
                ip, mask = _text(port, "IP"), _text(port, "SUBNET")
                break
        gateway = _text(engine, "GATEWAY") or _text(engine, "DEFAULT_GATEWAY")
        logical = node.find("WORKSPACE/LOGICAL")
        x = _float(_text(logical, "X")) if logical is not None else None
        y = _float(_text(logical, "Y")) if logical is not None else None
        device = PtDevice(ref=_text(engine, "SAVE_REF_ID") or str(index), name=name, kind=kind, model=model,
                          config=config, ip=ip, mask=mask, gateway=gateway, x=x, y=y,
                          routing="multilayer" in raw_type.lower() or bool(config and re.search(r"^ip routing", config, re.M)))
        devices.append(device)
        refs[device.ref] = refs[str(index)] = device
    links = []
    for cable in root.iter("CABLE"):
        ends = [_text(cable, "FROM"), _text(cable, "TO")]
        ports = [(p.text or "").strip() or None for p in cable.findall("PORT")] + [None, None]
        if all(e in refs for e in ends):
            links.append((refs[ends[0]].ref, ports[0], refs[ends[1]].ref, ports[1]))
    flows = []
    for pdu in root.iter("PDU"):
        source, destination = _text(pdu, "SOURCE") or _text(pdu, "SRC"), _text(pdu, "DESTINATION") or _text(pdu, "DEST")
        src = refs.get(source or "") or next((d for d in devices if d.name == source), None)
        dst = refs.get(destination or "") or next((d for d in devices if d.name == destination or d.ip == destination), None)
        if src and dst and src is not dst:
            flows.append((src.ref, dst.ref, "icmp"))
    for device in devices:
        if device.kind in ("pc", "server") and device.ip:
            device.nic = next((port for a, p, b, q in links for ref, port in ((a, p), (b, q)) if ref == device.ref and port), None)
    name = _text(root, "NETWORK/NAME") or fallback_name
    return PtTopology(name=name, devices=devices, links=links, flows=flows, version=_text(root, "VERSION"))
