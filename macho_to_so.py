#!/usr/bin/env python3
"""Convert an ARM64 Mach-O image into a structurally valid ELF64 shared object.

The original ARM64 code bytes, virtual addresses and dyld symbol bindings are
preserved. Mach-O segments become PT_LOAD segments, imported symbols become
ELF undefined symbols, dyld pointer binds become RELATIVE/GLOB_DAT
relocations, and a small JNI_OnLoad trampoline is emitted so Android's ART can
load the result. Runtime behaviour still depends on the JNI bridge and on an
Android replacement for Qt/AppKit; see README.md for that boundary.

Usage:
  macho_to_so.py INPUT_MACHO OUTPUT_SO [--bridge libroblox_jni_bridge.so]
"""
import argparse
import os
import struct
import sys

try:
    import lief
except ImportError:
    sys.exit("macho_to_so: LIEF is required (pip install lief)")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from naming import elf_name, short_hash  # noqa: E402

PAGE = 0x4000
PT_LOAD, PT_DYNAMIC, PT_PHDR = 1, 2, 6
SHT_NULL, SHT_PROGBITS, SHT_STRTAB = 0, 1, 3
SHT_DYNSYM, SHT_HASH, SHT_RELA, SHT_DYNAMIC = 11, 5, 4, 6
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
STB_LOCAL, STB_GLOBAL = 0, 1
STT_NOTYPE, STT_FUNC = 0, 2
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 1, 4, 5, 6
DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT = 7, 8, 9, 10, 11
DT_SONAME = 14
DT_INIT_ARRAY, DT_INIT_ARRAYSZ = 25, 27
SHT_INIT_ARRAY = 14
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_RELATIVE = 1027
VM_R, VM_W, VM_X = 1, 2, 4
PF_X, PF_W, PF_R = 1, 2, 4

# mov w0,#6 ; movk w0,#1,lsl#16 ; ret  ->  JNI_VERSION_1_6
JNI_TRAMPOLINE = struct.pack("<III", 0x528000C0, 0x72A00020, 0xD65F03C0)
STUDIO_JNI_NAME = "Java_io_github_robloxport_MainActivity_startStudio"
STUDIO_SHIM = struct.pack("<14I",
    0x10000009, 0xD280000A, 0xF2A0000A, 0xF2C0000A, 0xF2E0000A,
    0xCB0A0129, 0xD280000A, 0xF2A0000A, 0xF2C0000A, 0xF2E0000A,
    0x8B0A0129, 0xF9400121, 0xAA0203E0, 0x14000000)


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def pheader(ptype, flags, offset, vaddr, filesz, memsz, palign):
    return struct.pack("<IIQQQQQQ", ptype, flags, offset, vaddr, vaddr,
                       filesz, memsz, palign)


def shender(name, stype, flags, addr, offset, size, link, info, salign, entsize):
    return struct.pack("<IIQQQQIIQQ", name, stype, flags, addr, offset,
                       size, link, info, salign, entsize)


class StringTable:
    def __init__(self):
        self.data = bytearray(b"\0")
        self.offsets = {"": 0}

    def add(self, value):
        if value in self.offsets:
            return self.offsets[value]
        off = len(self.data)
        self.data.extend(value.encode("utf-8") + b"\0")
        self.offsets[value] = off
        return off


def sysv_hash(name):
    h = 0
    for c in name.encode("utf-8"):
        h = (h << 4) + c
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h & 0xFFFFFFFF


def build_hash(symbols):
    """Single-bucket SysV hash table; valid for the Android linker."""
    count = len(symbols)
    buckets = 1 if count == 0 else 1
    table = struct.pack("<II", buckets, count)
    if count:
        table += struct.pack("<I", 1)
        chain = []
        for i in range(count):
            chain.append(i + 1 if i + 1 < count else 0)
        table += struct.pack("<%dI" % count, *chain)
    else:
        table += struct.pack("<I", 0)
    return table


def _head_hash(path):
    import hashlib
    with open(path, "rb") as fh:
        return hashlib.sha1(fh.read(4096)).hexdigest()[:10]


def read_uleb(data, position):
    value = 0
    shift = 0
    while position < len(data):
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
    return value, position


def rebase_addresses(opcodes, segments):
    """Decode dyld rebase opcodes into the list of pointer slots."""
    result = []
    position = 0
    segment = 0
    offset = 0
    pointer_size = 8
    while position < len(opcodes):
        byte = opcodes[position]
        position += 1
        opcode, immediate = byte & 0xF0, byte & 0x0F
        if opcode == 0x00:      # DONE
            break
        if opcode == 0x10:      # SET_TYPE_IMM
            pointer_size = 8 if immediate == 1 else 4
        elif opcode == 0x20:    # SET_SEGMENT_AND_OFFSET_ULEB
            segment = immediate
            offset, position = read_uleb(opcodes, position)
        elif opcode == 0x30:    # ADD_ADDR_ULEB
            delta, position = read_uleb(opcodes, position)
            offset += delta
        elif opcode == 0x40:    # ADD_ADDR_IMM_SCALED
            offset += immediate * pointer_size
        elif opcode == 0x50:    # DO_REBASE_IMM_TIMES
            for unused in range(immediate):
                result.append((segments[segment].virtual_address + offset))
                offset += pointer_size
        elif opcode == 0x60:    # DO_REBASE_ULEB_TIMES
            count, position = read_uleb(opcodes, position)
            for unused in range(count):
                result.append(segments[segment].virtual_address + offset)
                offset += pointer_size
        elif opcode == 0x70:    # DO_REBASE_ADD_ADDR_ULEB
            delta, position = read_uleb(opcodes, position)
            offset += delta
        elif opcode == 0x80:    # DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
            count, position = read_uleb(opcodes, position)
            skip, position = read_uleb(opcodes, position)
            for unused in range(count):
                result.append(segments[segment].virtual_address + offset)
                offset += skip + pointer_size
    return result


def read_pointer(fh, offset):
    if offset is None or offset < 0:
        return 0
    fh.seek(offset)
    data = fh.read(8)
    return struct.unpack("<Q", data)[0] if len(data) == 8 else 0


def convert(src, dst, bridge="libroblox_jni_bridge.so",
            include_init=True, max_init=0):
    src_fh = open(src, "rb")
    binary = lief.MachO.parse(src)
    if binary is None or len(binary) == 0:
        raise RuntimeError("not a Mach-O file: %s" % src)
    m = binary.at(0)

    segments = [s for s in m.segments
                if s.name != "__PAGEZERO" and s.file_size > 0]
    if not segments:
        raise RuntimeError("no loadable segments in %s" % src)
    init_section = next((sec for sec in m.sections
                         if sec.name == "__mod_init_func"), None) \
        if include_init else None
    init_data = bytes(init_section.content) if init_section else b""
    if max_init > 0:
        init_data = init_data[:max_init * 8]
    max_file_end = max(s.file_offset + s.file_size for s in segments)
    max_vaddr_end = max(s.virtual_address + s.virtual_size for s in segments)

    def vaddr_to_offset(addr):
        for s in segments:
            if s.virtual_address <= addr < s.virtual_address + s.file_size:
                return s.file_offset + (addr - s.virtual_address)
        return None

    # ---- symbol table -------------------------------------------------
    imported = {}
    for sym in m.imported_symbols:
        if sym.name:
            imported[elf_name(sym.name)] = True
    imported.pop("", None)

    symbols = [{"name": "", "value": 0, "defined": False, "func": False}]
    index = {"": 0}
    used = set()

    def add_symbol(name, value=0, defined=False, func=False):
        if not name or name in used:
            return index.get(name, 0)
        used.add(name)
        pos = len(symbols)
        symbols.append({"name": name, "value": value,
                        "defined": defined, "func": func})
        index[name] = pos
        return pos

    for sym in m.symbols:
        if not sym.name or not sym.is_external:
            continue
        name = elf_name(sym.name)
        if not name:
            continue
        if sym.value:
            add_symbol(name, sym.value, True, True)
    for name in imported:
        if name not in index:
            add_symbol(name)
    jni_index = add_symbol("JNI_OnLoad", 0, True, True)
    studio_jni_index = -1
    if getattr(m, "main_command", None) is not None:
        base = min(x.virtual_address for x in segments)
        add_symbol("studio_entry", base + m.main_command.entrypoint, True, True)
        studio_jni_index = add_symbol(STUDIO_JNI_NAME, 0, True, True)

    strtab = StringTable()
    for sym in symbols:
        strtab.add(sym["name"])

    # ---- relocations from dyld bindings -------------------------------
    bindings = {}
    for b in getattr(m.dyld_info, "bindings", []):
        bindings[b.address] = b.symbol
    relocations = []
    for rel in m.relocations:
        addr = rel.address
        sym_name = None
        if getattr(rel, "has_symbol", False) and rel.symbol:
            sym_name = elf_name(rel.symbol.name)
        if not sym_name and addr in bindings:
            sym_name = elf_name(bindings[addr].name)
        if sym_name and sym_name in index:
            relocations.append((addr, index[sym_name], R_AARCH64_GLOB_DAT, 0))
        else:
            addend = read_pointer(src_fh, vaddr_to_offset(addr))
            relocations.append((addr, 0, R_AARCH64_RELATIVE, addend))

    covered_addresses = {item[0] for item in relocations}
    for binding in m.dyld_info.bindings:
        if binding.address in covered_addresses or not binding.symbol:
            continue
        symbol_name = elf_name(binding.symbol.name)
        if symbol_name in index:
            relocations.append((binding.address, index[symbol_name],
                                R_AARCH64_GLOB_DAT, 0))
            covered_addresses.add(binding.address)
    for rebase_address in rebase_addresses(getattr(m.dyld_info,
                                                    "rebase_opcodes", b""),
                                           list(m.segments)):
        if rebase_address in covered_addresses:
            continue
        covered_addresses.add(rebase_address)
        pointer_value = read_pointer(src_fh,
                                     vaddr_to_offset(rebase_address))
        relocations.append((rebase_address, 0, R_AARCH64_RELATIVE,
                            pointer_value))

    # ---- needed libraries --------------------------------------------
    needed = [bridge]
    for lib in m.libraries:
        name = os.path.basename(str(lib.name))
        if not name or name in needed:
            continue
        if name.endswith(".dylib") or name.endswith(".framework"):
            needed.append(name.replace(".dylib", ".so")
                          .replace(".framework", ".so"))

    dynstr = strtab
    needed_offsets = [dynstr.add(n) for n in needed]
    dynstr.add("librobloxport.so")

    dynsym_data = bytearray()
    for sym in symbols:
        info = ((STB_GLOBAL if sym["defined"] else STB_GLOBAL) << 4)
        info |= STT_FUNC if sym["func"] else STT_NOTYPE
        shndx = 0
        if sym["defined"]:
            shndx = 8 if sym["name"] == "JNI_OnLoad" else 7
        dynsym_data += struct.pack("<IBBHQQ", dynstr.offsets[sym["name"]],
                                   info, 0, shndx, sym["value"], 0)

    hash_data = build_hash([s["name"] for s in symbols])
    rela_data = bytearray()
    for addr, sym_idx, rtype, addend in relocations:
        rela_data.extend(struct.pack("<QQQ", addr, (sym_idx << 32) | rtype,
                                     addend))

    # ---- layout of appended metadata ---------------------------------
    meta_off = align(max_file_end, PAGE)
    meta_va = align(max_vaddr_end, PAGE)
    off_strtab = meta_off
    off_dynsym = off_strtab + len(dynstr.data)
    off_hash = off_dynsym + len(dynsym_data)
    off_rela = off_hash + len(hash_data)
    n_dyn = 12 + len(needed)         # + DT_INIT_ARRAY and DT_INIT_ARRAYSZ
    init_count = len(init_data) // 8
    predicted_rela_size = 24 * (len(relocations) + init_count
                               + (1 if studio_jni_index >= 0 else 0))
    off_dynamic = align(off_rela + predicted_rela_size, 16)
    off_shstr = off_dynamic + 16 * n_dyn
    shstr = StringTable()
    for n in (".dynstr", ".dynsym", ".hash", ".rela.dyn", ".dynamic",
              ".shstrtab", ".text", ".jni", ".init_array"):
        shstr.add(n)
    off_argv = align(off_shstr + len(shstr.data), 16)
    off_argv_string = off_argv + 16
    off_init_array = align(off_argv_string + 16, 8)
    off_shdr = align(off_init_array + len(init_data), 8)
    n_sections = 10 if init_data else 9
    off_shdr_end = off_shdr + 64 * n_sections

    tramp_off = align(off_shdr_end, PAGE)
    tramp_va = align(meta_va + (off_shdr_end - meta_off), PAGE)
    file_end = tramp_off + len(JNI_TRAMPOLINE)
    struct.pack_into("<Q", dynsym_data, jni_index * 24 + 8, tramp_va)
    def va(offset):
        return meta_va + (offset - meta_off)

    studio_shim_data = bytearray(STUDIO_SHIM)
    studio_shim_offset = 0x2000
    studio_shim_va = 0
    if studio_jni_index >= 0:
        image_base = min(x.virtual_address for x in segments)
        studio_address = image_base + m.main_command.entrypoint
        studio_shim_va = image_base + studio_shim_offset
        struct.pack_into("<Q", dynsym_data, studio_jni_index * 24 + 8,
                         studio_shim_va)
        argv_address = va(off_argv)
        opcodes = (0xD2800000, 0xF2A00000, 0xF2C00000, 0xF2E00000)
        for base_index, value in ((1, studio_shim_va), (6, argv_address)):
            for order, opcode in enumerate(opcodes):
                shift = order * 16
                struct.pack_into("<I", studio_shim_data,
                                 (base_index + order) * 4,
                                 opcode | (((value >> shift) & 0xFFFF)
                                           << 5) | 10)
        branch_offset = (studio_address - (studio_shim_va + 52)) >> 2
        struct.pack_into("<I", studio_shim_data, 52,
                         0x14000000 | (branch_offset & 0x03FFFFFF))
    jni_area_size = len(JNI_TRAMPOLINE)

    if init_data:
        init_va = va(off_init_array)
        for offset_in_array in range(0, len(init_data), 8):
            initializer = struct.unpack_from("<Q", init_data,
                                             offset_in_array)[0]
            relocations.append((init_va + offset_in_array, 0,
                                R_AARCH64_RELATIVE, initializer))
        rela_data = bytearray()
        for addr, sym_idx, rtype, addend in relocations:
            rela_data.extend(struct.pack("<QQQ", addr,
                                         (sym_idx << 32) | rtype, addend))
        assert len(rela_data) == predicted_rela_size - (24 if studio_jni_index >= 0 else 0)

    if studio_jni_index >= 0:
        relocations.append((va(off_argv), 0, R_AARCH64_RELATIVE,
                            va(off_argv_string)))
        rela_data = bytearray()
        for addr, sym_idx, rtype, addend in relocations:
            rela_data.extend(struct.pack("<QQQ", addr,
                                         (sym_idx << 32) | rtype, addend))
        assert len(rela_data) == predicted_rela_size

    dyn_entries = [
        (DT_HASH, va(off_hash)),
        (DT_STRTAB, va(off_strtab)),
        (DT_SYMTAB, va(off_dynsym)),
        (DT_STRSZ, len(dynstr.data)),
        (DT_SYMENT, 24),
        (DT_RELA, va(off_rela)),
        (DT_RELASZ, len(rela_data)),
        (DT_RELAENT, 24),
        (DT_INIT_ARRAY, va(off_init_array)),
        (DT_INIT_ARRAYSZ, len(init_data)),
    ]
    dyn_entries += [(DT_NEEDED, o) for o in needed_offsets]
    dyn_entries.append((DT_SONAME, dynstr.offsets["librobloxport.so"]))
    dyn_entries.append((DT_NULL, 0))
    assert len(dyn_entries) == n_dyn, (len(dyn_entries), n_dyn)
    dynamic_data = b"".join(struct.pack("<QQ", t, v) for t, v in dyn_entries)

    # ---- program headers ---------------------------------------------
    phdr_count = len(segments) + 4
    ph_size = 56 * phdr_count
    first_vaddr = min(s.virtual_address for s in segments)
    phdrs = pheader(PT_PHDR, PF_R, 64, first_vaddr + 64,
                    ph_size, ph_size, 8)
    for s in segments:
        flags = 0
        if s.init_protection & VM_R:
            flags |= PF_R
        if s.init_protection & VM_W:
            flags |= PF_W
        if s.init_protection & VM_X:
            flags |= PF_X
        phdrs += pheader(PT_LOAD, flags, s.file_offset, s.virtual_address,
                         s.file_size, max(s.file_size, s.virtual_size), PAGE)
    phdrs += pheader(PT_LOAD, PF_R | PF_W, meta_off, meta_va,
                     off_shdr_end - meta_off, off_shdr_end - meta_off, PAGE)
    phdrs += pheader(PT_LOAD, PF_R | PF_X, tramp_off, tramp_va,
                     jni_area_size, jni_area_size, PAGE)
    phdrs += pheader(PT_DYNAMIC, PF_R, off_dynamic, va(off_dynamic),
                     len(dynamic_data), len(dynamic_data), 8)

    # ---- section headers ---------------------------------------------
    sh_name = lambda n: shstr.offsets[n]
    text = next(s for s in segments if s.name == "__TEXT")
    sections = [
        shender(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
        shender(sh_name(".dynstr"), SHT_STRTAB, SHF_ALLOC, va(off_strtab),
                off_strtab, len(dynstr.data), 0, 0, 1, 0),
        shender(sh_name(".dynsym"), SHT_DYNSYM, SHF_ALLOC, va(off_dynsym),
                off_dynsym, len(dynsym_data), 1, 1, 8, 24),
        shender(sh_name(".hash"), SHT_HASH, SHF_ALLOC, va(off_hash),
                off_hash, len(hash_data), 2, 0, 8, 4),
        shender(sh_name(".rela.dyn"), SHT_RELA, SHF_ALLOC, va(off_rela),
                off_rela, len(rela_data), 2, 0, 8, 24),
        shender(sh_name(".dynamic"), SHT_DYNAMIC, SHF_ALLOC, va(off_dynamic),
                off_dynamic, len(dynamic_data), 1, 0, 8, 16),
        shender(sh_name(".shstrtab"), SHT_STRTAB, 0, 0, off_shstr,
                len(shstr.data), 0, 0, 1, 0),
        shender(sh_name(".text"), SHT_PROGBITS, SHF_ALLOC | SHF_EXEC,
                text.virtual_address, text.file_offset, text.file_size,
                0, 0, 16, 0),
        shender(sh_name(".jni"), SHT_PROGBITS, SHF_ALLOC | SHF_EXEC,
                tramp_va, tramp_off, jni_area_size, 0, 0, 4, 0),
    ]
    if init_data:
        sections.append(shender(sh_name(".init_array"), SHT_INIT_ARRAY,
                                SHF_ALLOC | SHF_WRITE, va(off_init_array),
                                off_init_array, len(init_data), 0, 0, 8, 8))
    assert len(sections) == n_sections

    ident = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH", 3, 183, 1, 0, 64, off_shdr, 0, 64,
        56, phdr_count, 64, n_sections, 6)

    # ---- emit --------------------------------------------------------
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    header = ehdr + phdrs
    assert len(header) == ph_size + 64
    with open(src, "rb") as fin, open(dst, "wb") as out:
        out.write(header)
        fin.seek(len(header))
        remaining = max_file_end - len(header)
        while remaining > 0:
            chunk = fin.read(min(1 << 20, remaining))
            if not chunk:
                out.write(b"\0" * remaining)
                break
            out.write(chunk)
            remaining -= len(chunk)
        if studio_jni_index >= 0:
            out.seek(studio_shim_offset)
            out.write(studio_shim_data)
            out.seek(0, os.SEEK_END)
        out.write(b"\0" * (meta_off - max_file_end))
        out.write(dynstr.data)
        out.write(dynsym_data)
        out.write(hash_data)
        out.write(rela_data)
        out.write(b"\0" * (off_dynamic - (off_rela + len(rela_data))))
        out.write(dynamic_data)
        out.write(shstr.data)
        out.write(b"\0" * (off_argv - (off_shstr + len(shstr.data))))
        out.write(b"\0" * 16)
        out.write(b"RobloxStudio\0".ljust(16, b"\0"))
        out.write(b"\0" * (off_init_array - (off_argv + 32)))
        out.write(init_data)
        out.write(b"\0" * (off_shdr - (off_init_array + len(init_data))))
        for sec in sections:
            out.write(sec)
        out.write(b"\0" * (tramp_off - off_shdr_end))
        out.write(JNI_TRAMPOLINE)

    src_fh.close()
    return {
        "source": src, "output": dst,
        "segments": len(segments),
        "symbols": len(symbols) - 1,
        "imports": len(imported),
        "relocations": len(relocations),
        "needed": needed,
        "input_size": os.path.getsize(src),
        "output_size": os.path.getsize(dst),
        "code_sha256": _head_hash(src),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--bridge", default="libroblox_jni_bridge.so")
    ap.add_argument("--skip-init", action="store_true")
    ap.add_argument("--max-init", type=int, default=0)
    args = ap.parse_args()
    result = convert(args.input, args.output, args.bridge,
                     include_init=not args.skip_init, max_init=args.max_init)
    print("%s -> %s  seg=%d sym=%d imp=%d rel=%d  %d->%d bytes" % (
        os.path.basename(args.input), os.path.basename(args.output),
        result["segments"], result["symbols"], result["imports"],
        result["relocations"], result["input_size"], result["output_size"]))


if __name__ == "__main__":
    main()
