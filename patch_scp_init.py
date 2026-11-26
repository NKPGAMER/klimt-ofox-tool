#!/usr/bin/env python3
"""Make scp.ko's module init return 0 immediately.

The MTK tinysys SCP driver panics when it probes inside recovery, but
goodix_core_dali.ko needs its exported symbols just to load. Replacing the
entry of init_module with `mov x0, #0; ret` keeps those symbols available
while the SCP hardware is never initialised.

Called from repack_twrp.py as: patch_scp_init(src, dst)
"""
import struct
from collections import namedtuple
from pathlib import Path

MOV_X0_0_RET = bytes.fromhex("000080d2c0035fd6")  # mov x0, #0 ; ret
SHT_SYMTAB = 2
SYM_SIZE = 24
Section = namedtuple("Section", "type offset size link info entsize")


def _sections(data):
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, _ = struct.unpack_from("<HHH", data, 0x3A)
    sections = []
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        _, sh_type = struct.unpack_from("<II", data, base)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, base + 0x18)
        sh_link, sh_info = struct.unpack_from("<II", data, base + 0x28)
        sh_entsize, = struct.unpack_from("<Q", data, base + 0x38)
        sections.append(Section(sh_type, sh_offset, sh_size, sh_link, sh_info, sh_entsize))
    return sections


def _symbol_name(data, strtab, st_name):
    start = strtab.offset + st_name
    return data[start:data.index(b"\0", start)].decode("ascii", "replace")


def patch_scp_init(src: str, dst: str) -> bool:
    data = bytearray(Path(src).read_bytes())
    if bytes(data[:4]) != b"\x7fELF":
        raise SystemExit(f"not an ELF file: {src}")
    sections = _sections(data)
    symtabs = [s for s in sections if s.type == SHT_SYMTAB]
    if len(symtabs) != 1:
        raise SystemExit(f"{src}: expected exactly one SHT_SYMTAB section")
    symtab = symtabs[0]
    strtab = sections[symtab.link]
    for index in range(symtab.size // SYM_SIZE):
        base = symtab.offset + index * SYM_SIZE
        st_name, _, _, st_shndx = struct.unpack_from("<IBBH", data, base)
        st_value, = struct.unpack_from("<Q", data, base + 0x8)
        if _symbol_name(data, strtab, st_name) != "init_module":
            continue
        entry = sections[st_shndx].offset + st_value
        data[entry:entry + len(MOV_X0_0_RET)] = MOV_X0_0_RET
        Path(dst).write_bytes(data)
        print(f"scp.ko: init_module entry 0x{entry:x} -> mov x0, #0; ret")
        return True
    raise SystemExit(f"{src}: init_module symbol not found")
