#!/usr/bin/env python3
"""Drop SCP symbol references from a module ELF.

Once patch_goodix_scp has stubbed the call sites, the relocations and the
undefined scp_* symbols are dead weight -- and the module loader resolves
every undefined symbol at load time, so goodix_core_dali.ko would still
refuse to load without scp.ko. This strips both: the relocation entries
referencing scp_* and the scp_* undefined symbols themselves (the remaining
symbol indices are renumbered accordingly).

Run as: remove_scp_symbols.py <input.ko> <output.ko>
"""
import argparse
import struct
from collections import namedtuple
from pathlib import Path

SCP_PREFIX = "scp_"
SHT_SYMTAB, SHT_RELA = 2, 4
SHN_UNDEF, STB_LOCAL = 0, 0
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = bytearray(args.input.read_bytes())
    if bytes(data[:4]) != b"\x7fELF":
        raise SystemExit(f"not an ELF file: {args.input}")
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, _, _ = struct.unpack_from("<HHH", data, 0x3A)
    sections = _sections(data)
    symtabs = [i for i, s in enumerate(sections) if s.type == SHT_SYMTAB]
    if len(symtabs) != 1:
        raise SystemExit("expected exactly one SHT_SYMTAB section")
    symtab_index = symtabs[0]
    symtab = sections[symtab_index]
    strtab = sections[symtab.link]

    entries = []
    for index in range(symtab.size // SYM_SIZE):
        base = symtab.offset + index * SYM_SIZE
        entries.append(bytearray(data[base:base + SYM_SIZE]))
    removed = set()
    for index, entry in enumerate(entries):
        st_name, = struct.unpack_from("<I", entry, 0)
        st_shndx, = struct.unpack_from("<H", entry, 0x6)
        if _symbol_name(data, strtab, st_name).startswith(SCP_PREFIX) and st_shndx == SHN_UNDEF:
            removed.add(index)

    index_map, kept = {}, []
    for index, entry in enumerate(entries):
        if index in removed:
            continue
        index_map[index] = len(kept)
        kept.append(entry)
    first_global = len(kept)
    for index, entry in enumerate(kept):
        if entry[0x4] >> 4 != STB_LOCAL:
            first_global = index
            break

    symtab_blob = b"".join(kept)
    data[symtab.offset:symtab.offset + len(symtab_blob)] = symtab_blob
    shdr = e_shoff + symtab_index * e_shentsize
    struct.pack_into("<Q", data, shdr + 0x20, len(symtab_blob))  # sh_size
    struct.pack_into("<I", data, shdr + 0x2C, first_global)      # sh_info

    dropped = 0
    for index, rela in enumerate(sections):
        if rela.type != SHT_RELA:
            continue
        out = bytearray()
        for entry in range(rela.size // RELA_SIZE):
            base = rela.offset + entry * RELA_SIZE
            blob = bytearray(data[base:base + RELA_SIZE])
            r_info, = struct.unpack_from("<Q", blob, 0x8)
            sym_index, r_type = r_info >> 32, r_info & 0xFFFFFFFF
            if sym_index in removed:
                dropped += 1
                continue
            struct.pack_into("<Q", blob, 0x8, (index_map[sym_index] << 32) | r_type)
            out += blob
        data[rela.offset:rela.offset + len(out)] = out
        shdr = e_shoff + index * e_shentsize
        struct.pack_into("<Q", data, shdr + 0x20, len(out))      # sh_size

    args.output.write_bytes(data)
    print(f"removed {len(removed)} scp symbol(s), {dropped} relocation(s)")


if __name__ == "__main__":
    main()
