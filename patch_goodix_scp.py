#!/usr/bin/env python3
"""Stub the SCP function calls inside goodix_core_dali.ko.

goodix_core_dali.ko calls into the tinysys SCP driver (scp_A_register_notify,
scp_get_reserve_mem_* and friends). In recovery those calls would run against
dead hardware, so every `bl <undefined scp_*>` relocation site is rewritten to
`mov x0, #0`: a one-instruction stub that makes the call return 0 without
going anywhere. Those calls decide whether the SCP touch path arms itself,
so returning 0 keeps that path dormant.

Only UNDEFINED scp_* symbols are touched: the module's own scp_tp_* code
stays intact. Non-call references (scp_ipidev data accesses) cannot be
stubbed and are left for remove_scp_symbols to drop.

Called from repack_twrp.py as: patch_goodix_scp(src, dst) -> bool
"""
import struct
from collections import namedtuple
from pathlib import Path

MOV_X0_0 = bytes.fromhex("000080d2")  # mov x0, #0
R_AARCH64_CALL26 = 283
SHT_SYMTAB, SHT_RELA = 2, 4
SCP_PREFIX = "scp_"
SYM_SIZE, RELA_SIZE = 24, 24
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


def patch_module(src: str, dst: str) -> bool:
    data = bytearray(Path(src).read_bytes())
    if bytes(data[:4]) != b"\x7fELF":
        print(f"not an ELF file: {src}")
        return False
    sections = _sections(data)
    symtabs = [i for i, s in enumerate(sections) if s.type == SHT_SYMTAB]
    if len(symtabs) != 1:
        print("expected exactly one SHT_SYMTAB section")
        return False
    symtab_index = symtabs[0]
    symtab = sections[symtab_index]
    strtab = sections[symtab.link]
    names, undefined = [], []
    for index in range(symtab.size // SYM_SIZE):
        base = symtab.offset + index * SYM_SIZE
        st_name, _, _, st_shndx = struct.unpack_from("<IBBH", data, base)
        names.append(_symbol_name(data, strtab, st_name))
        undefined.append(st_shndx == 0)
    stubbed, deferred = [], []
    for rela in (s for s in sections if s.type == SHT_RELA and s.link == symtab_index):
        target = sections[rela.info]
        for index in range(rela.size // RELA_SIZE):
            base = rela.offset + index * RELA_SIZE
            r_offset, r_info, _ = struct.unpack_from("<QQq", data, base)
            sym_index, r_type = r_info >> 32, r_info & 0xFFFFFFFF
            if sym_index >= len(names):
                continue
            name = names[sym_index]
            if not name.startswith(SCP_PREFIX) or not undefined[sym_index]:
                continue
            if r_type != R_AARCH64_CALL26:
                deferred.append(f"{name} (relocation type {r_type})")
                continue
            at = target.offset + r_offset
            data[at:at + 4] = MOV_X0_0
            stubbed.append(name)
    Path(dst).write_bytes(data)
    print(f"stubbed {len(stubbed)} SCP call site(s): {', '.join(sorted(set(stubbed))) or 'none'}")
    if deferred:
        print(f"deferred {len(deferred)} non-call SCP reference(s) to remove_scp_symbols: "
              f"{', '.join(sorted(set(deferred)))}")
    return True
