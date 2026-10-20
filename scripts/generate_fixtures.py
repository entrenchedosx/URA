import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
FIXTURES.mkdir(parents=True, exist_ok=True)

CODE = bytes.fromhex(
    "55"
    "48 89 E5"
    "E8 17 00 00 00"
    "B8 2A 00 00 00"
    "48 83 C4 20"
    "5D"
    "C3"
    "90 90 90 90 90 90 90 90 90 90 90 90"
    "55"
    "48 89 E5"
    "31 C0"
    "83 C0 01"
    "83 F8 05"
    "7C F8"
    "5D"
    "C3"
    "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90"
)
ASCII_STRING = b"URA fixture string\0"
WIDE_STRING = "Wide URA".encode("utf-16le") + b"\0\0"
RDATA = ASCII_STRING + b"\0" * (0x60 - len(ASCII_STRING)) + WIDE_STRING
RDATA = RDATA.ljust(0x200, b"\0")


def build_pe():
    image_base = 0x140000000
    data = bytearray(0x600)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        2,
        0,
        0,
        0,
        0xF0,
        0x0022,
    )
    data[0x84:0x84 + len(file_header)] = file_header
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    optional[2] = 1
    optional[4] = 0
    struct.pack_into("<III", optional, 4, 0x200, 0x200, 0)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 20, 0x1000)
    struct.pack_into("<Q", optional, 24, image_base)
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", optional, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", optional, 56, 0x3000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<H", optional, 70, 0)
    struct.pack_into("<QQQQ", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", optional, 108, 16)
    data[0x98:0x98 + len(optional)] = optional
    section_table = 0x98 + len(optional)
    text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    rdata = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\0\0",
        0x200,
        0x2000,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    data[section_table:section_table + len(text)] = text
    data[section_table + 40:section_table + 40 + len(rdata)] = rdata
    data[0x200:0x200 + len(CODE)] = CODE
    data[0x400:0x400 + len(RDATA)] = RDATA
    return bytes(data)


def build_elf():
    data = bytearray(0x3200)
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1
    data[0:16] = ident
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000, 64, 0x3000, 0, 64, 56, 3, 64, 4, 3)
    phdrs = [
        (4, 0, 0x400000, 0x400000, 0x200, 0x200, 0x1000),
        (5, 0x1000, 0x401000, 0x401000, 0x200, 0x200, 0x1000),
        (4, 0x2000, 0x402000, 0x402000, 0x200, 0x200, 0x1000),
    ]
    for index, phdr in enumerate(phdrs):
        struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, 1, *phdr)
    data[0x1000:0x1000 + len(CODE)] = CODE
    data[0x2000:0x2000 + len(RDATA)] = RDATA
    shstr = b"\0.text\0.rdata\0.shstrtab\0"
    data[0x3100:0x3100 + len(shstr)] = shstr
    shoff = 0x3000
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0x401000, 0x1000, 0x200, 0, 0, 16, 0),
        (7, 1, 2, 0x402000, 0x2000, 0x200, 0, 0, 16, 0),
        (14, 3, 0, 0, 0x3100, len(shstr), 0, 0, 1, 0),
    ]
    for index, section in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", data, shoff + index * 64, *section)
    return bytes(data)


(FIXTURES / "ura64.exe").write_bytes(build_pe())
(FIXTURES / "ura64.elf").write_bytes(build_elf())
print("fixtures written")
