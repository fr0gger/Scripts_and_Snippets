from qiling import *
from qiling.const import *
import sys
import pefile
from capstone import *


# Load PE with capstone
def loader_pe(pe):
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    data = pe.get_memory_mapped_image()[entry_point:]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    rdbin = cs.disasm(data, 0x10000)
    return rdbin


# check architecture
def check_arch(pe):
    if pe.FILE_HEADER.Machine == 0x14c:
        bit = 32
        # print(bit)
    elif pe.FILE_HEADER.Machine == 0x8664:
        bit = 64
        # print(bit)
    print("[+] Sample is %s bit" % bit)
    return bit


# Hook for GetProcAddress
def GetProcAddress(ql, addr, params):
    print(params)
    return addr, params


# stop exec at the given address
def stop(ql):
    ql.nprint("[+] Address found")
    ql.console = False
    ql.emu_stop()


# sandbox to emulate the EXE
def my_sandbox(path, rootfs):
    # setup Qiling engine
    ql = Qiling(path, rootfs)  # , output = "debug")

    # Patch address
    # ql.patch(0x0042B726, b'\x90\x90\x90')

    # Hook address
    ql.hook_address(stop, 0x0042B726)

    # hook GetProcAddress() on exit
    ql.set_api("GetProcAddress", GetProcAddress, QL_INTERCEPT.EXIT)

    # disable strace logs
    ql.filter = []
    # now emulate the EXE
    ql.run()


if __name__ == "__main__":

    exefile = sys.argv[1]
    try:
        exe = pefile.PE(exefile)
    except OSError as e:
        print(e)
        sys.exit()
    except pefile.PEFormatError as e:
        print(module.config.R + "[-] PEFormatError: %s" % e.value)
        print(module.config.R + "[!] The file is not a valid PE")
        sys.exit()

    rdbin = loader_pe(exe)
    check_arch(exe)

    # Run the execution
    my_sandbox([exefile], "examples/rootfs/x86_windows")
