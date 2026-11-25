#!/usr/bin/env python3
"""Self-test: convert the bundled Mach-O fixture and check the ELF output."""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "tests_fixture.macho")


def main():
    import lief
    with tempfile.TemporaryDirectory(prefix="macho2so-selftest-") as tmp:
        out = os.path.join(tmp, "NativeDialog.so")
        subprocess.run([sys.executable, os.path.join(HERE, "macho_to_so.py"),
                        FIXTURE, out], check=True)
        elf = lief.ELF.parse(out)
        assert str(elf.header.file_type) == "FILE_TYPE.DYN", elf.header.file_type
        assert str(elf.header.machine_type) == "ARCH.AARCH64"
        names = set(str(n) for n in elf.libraries)
        assert "libroblox_jni_bridge.so" in names, names
        assert elf.get_symbol("JNI_OnLoad") is not None
        assert elf.get_symbol("JNI_OnLoad").value != 0
        assert len(elf.dynamic_relocations) > 0
        print("selftest OK: %d segments, %d symbols, %d relocations" %
              (len(elf.segments), len(elf.dynamic_symbols),
               len(elf.dynamic_relocations)))


if __name__ == "__main__":
    main()
