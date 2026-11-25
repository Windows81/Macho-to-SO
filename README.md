# macho2so

Standalone converter: ARM64 Mach-O executable or dylib -> ELF64 AArch64
shared object. Requires Python 3, LIEF and a `clang`/`ld.lld` toolchain only
for the optional load test (the converter itself needs just LIEF).

    pip install lief
    python3 macho_to_so.py INPUT OUTPUT [--bridge libroblox_jni_bridge.so]

What it does:

* maps each Mach-O segment to an ELF `PT_LOAD` with the same file bytes,
  virtual address and page protection;
* preserves exported symbols and turns imported Mach-O symbols into ELF
  undefined symbols (the leading Mach-O underscore is removed);
* converts dyld binds and rebase pointers into `R_AARCH64_GLOB_DAT` and
  `R_AARCH64_RELATIVE` relocations;
* emits a minimal SysV hash table, `.dynsym`, `.dynamic`, section headers and
  a three-instruction `JNI_OnLoad` trampoline returning `JNI_VERSION_1_6`;
* adds `DT_NEEDED` for the JNI bridge and for each macOS dylib, renamed to
  `.so`.

Verification:

    python3 selftest.py
    readelf -h OUTPUT        # Type DYN, Machine AArch64
    readelf -dW OUTPUT       # DT_HASH, DT_NEEDED, DT_RELA
    readelf -rW OUTPUT       # AArch64 relocations

`tests_fixture.macho` is a small Mach-O image taken from the Roblox Studio
bundle and bundled so the self-test runs without network access.

Licence: GNU General Public License v3 (see `LICENSE`).
