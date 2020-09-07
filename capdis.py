#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Thomas Roccia - Disassembling PE file
"""
import sys
import pefile
from capstone import *


# Load PE with capstone
def loader_pe(pe):
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    data = pe.get_memory_mapped_image()[entry_point:]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    rdbin = cs.disasm(data, 0x1000)
    return rdbin


# check architecture
def check_arch(pe):
    if pe.FILE_HEADER.Machine == 0x14c:
        bit = 32
        # print(bit)
    elif pe.FILE_HEADER.Machine == 0x8664:
        bit = 64
        # print(bit)
    return bit


# Check content of Import Address Table
def check_iat(pe):
    iat = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                iat.append(imp.name)
    except:
        pass
    iatcount = len(iat)

    try:
        iatlow = [x.lower() for x in iat]
    except (AttributeError, RuntimeError, TypeError, NameError):
        iatlow = 0
        pass
    return iatcount, iatlow


def main(exe):
    try:
        exe = pefile.PE(exe)
    except OSError as e:
        print(e)
        sys.exit()
    except pefile.PEFormatError as e:
        print(module.config.R + "[-] PEFormatError: %s" % e.value)
        print(module.config.R + "[!] The file is not a valid PE")
        sys.exit()

    rdbin = loader_pe(exe)
    iatcount, iatlow = check_iat(exe)
    bit = check_arch(exe)

    print("[+] Sample is %s bit" % bit)
    print("[+] Number of imported functions: %s " % iatcount)
    print("[+] List of imported function: ")
    for i in iatlow:
        print(i)

    print("[+] Binary disassembled: ")
    for i in rdbin:
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


if __name__ == '__main__':
    main(sys.argv[1])
