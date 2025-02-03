# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------


"""Quick-win thin wrapper around ucutils unicorn wrapper since too lazy too roll
own in Python.
"""
try:
    import unicorn
    if (
        unicorn.UC_VERSION_MAJOR == 2 and
        unicorn.UC_VERSION_MINOR >= 1
    ):
        # @TODO: unicorn added cosmetic updates that break how one instantiates
        #        a subclass. Add support eventually for both.
        raise ImportError("Unsupported 2.1.x unicorn version")
    import ucutils
    import ucutils.emu
    import ucutils.plat.win64
except ImportError as e:
    print(f"Error: Required module not found. {e}")
    print("Make sure you have 'unicorn' and `ucutile` installed.")
    print("\t`pip install unicorn` and `pip install ucutils")
    exit(1)

# ------------------------------------------------------------------------------
# Emulator
class EmulateIntel64(ucutils.emu.Emulator):
    PAGE_SIZE = 0x1000

    def __init__(self, *args, **kwargs):
        super(EmulateIntel64, self).__init__(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64,
                                             plat=ucutils.plat.win64,
                                             *args, **kwargs)
        # ----------------------------------------------------------------------
        # @TODO: bitte
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

    def map_image(self, code: bytes, address: int=0):
        map_size = ucutils.align(len(code), self.PAGE_SIZE)
        ea = 0 if not address else ucutils.align(address, self.PAGE_SIZE)
        self.mem.map_region(ea, map_size, reason="user_image")
        self.mem_write(ea, code)
        self.pc = ea

    def parse_u64(self, value):
        return ucutils.parse_uint64(self, value)
