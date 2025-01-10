"""
Thin wrapper around ucutils unicorn wrapper since too lazy too roll
my own in Python
"""

import unicorn
import ucutils
import ucutils.emu
import ucutils.plat.win64

# ---------------------------------------------------------------------------------------
# Emulator
class EmulateIntel64(ucutils.emu.Emulator):
    
    PAGE_SIZE = 0x1000

    def __init__(self, *args, **kwargs):
        super(EmulateIntel64, self).__init__(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64,
                                             plat=ucutils.plat.win64,
                                             *args, **kwargs)
        # ----------------------------------------------------------------------
        # @TODO(nean): come on
        self.base = 0xFFFFFFFF

        # ----------------------------------------------------------------------
        # Initialize the stack space directly
        ucutils.STACK_SIZE = 0x1000
        ucutils.STACK_ADDR = 0xFFFFFFFFFFFF0000
        self.mem.map_region(ucutils.STACK_ADDR, ucutils.STACK_SIZE, reason="stack")
        self.stack_pointer = ucutils.STACK_ADDR + 0x1000
        self.base_pointer  = ucutils.STACK_ADDR + 0x2000

    def map_teb(self):
        # Map gs segment
        # @NOTE: do this after the mapping as it can run into issues with
        #        mapping shellcode at 0 address
        self.plat.map_teb()

    def map_shellcode(self, code: bytes, address: int=0):
        map_size = ucutils.align(len(code), self.PAGE_SIZE)
        ea = 0 if not address else ucutils.align(address, self.PAGE_SIZE)

        self.mem.map_region(ea, map_size, reason="shellcode")
        self.mem_write(ea, code)
        self.pc = ea

    def add_hook_code_logger(self):
        def _cb(uc, address, size, user_data):
            buf = uc.mem_read(address, size)
            insn = next(self.dis.disasm(bytes(buf), address))
            print(f'0x{insn.address:014x}: {insn.mnemonic} {insn.op_str}')
        self.hook_add(unicorn.UC_HOOK_CODE, _cb)

    def parse_u64(self, value): 
        return ucutils.parse_uint64(self, value)

    def u(self, count: int=0):
        # @TODO(nean): `count`?? handle more than this most basic case
        buf = self.mem_read(self.pc, 15)
        insn = next(self.dis.disasm(bytes(buf), self.pc))
        print(f'0x{insn.address:014x}: {insn.mnemonic} {insn.op_str}')

    def db(self, address: int=-1, l: int=0x60):
        """WinDBG `db` equivalent"""
        ea = self.pc if address == -1 else address
        print(ucutils.mem_hexdump(self, ea, l))

    def dd(self, address: int=-1, l: int=0x10):
        ea = self.pc if address == -1 else address
        for i in range(l):
            try:
                q = ucutils.parse_uint32(self, ea + (i * 4))
            except unicorn.UcError:
                print("invalid memory")
                break
            print("0x%014x: %08x" % (ea + (i * 4), q))

    def dq(self, address: int=-1, l: int=0x10):
        ea = self.pc if address == -1 else address
        for i in range(l):
            try:
                q = ucutils.parse_uint64(self, ea + (i * 4))
            except unicorn.UcError:
                print("invalid memory")
                break
            print("0x%014x: %016x" % (ea + (i * 4), q))
