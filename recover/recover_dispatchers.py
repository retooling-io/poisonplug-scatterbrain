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

"""---------------------Instruction Dispatchers----------------------

Exposes the following high-level routine:
    - recover_instruction_dispatchers

This internally calls the emulator and static pushfq/popfq verifier.
"""

#-------------------------------------------------------------------------------
from recover.recover_core import (
    ProtectedInput64,
    x86Decoder, x86, x86Instr
)
#-------------------------------------------------------------------------------
def recover_instruction_dispatchers(
    d: ProtectedInput64
):
    """Resolves/removes the instruction dispatcher control flow obfuscation by
    transforming each ambigous `call DispatcherX` to a `jmp DispatchTarget`.

    Each dispatcher call's unique, dynamic destination is resolved upfront and
    replaced with a more linear `jmp dest`. This is the first transformation
    that needs to run as it makes it an easier base for the other passes.

    The following properties in the protected input image are updated on success:
      :jmppatchedbuffer:      updated imgbuffer that contains the resolved
                              dispatchers to 'jmp->target' instructions
      :mdp:                   disassembler for the jmp-patched img
      :dispatcher_locs:       starting locations for all dispatcher functions
      :dispatchers_to_target: dispatcher-to-target map
    """
    d.log.info("Starting instruction dispatcher recovery")
    #---------------------------------------------------------------------------
    _recover_all_dispatchers_via_emu(d)
    if len(d.dispatchers_to_target) == 0:
        raise ValueError("Need to recover the dispatchers first")
    #---------------------------------------------------------------------------
    d.log.info("Applying all resolved `jmp->dest` patches for each dispatcher")
    d.jmppatchedbuffer = d.imgbuffer
    def _apply_call_to_jmp_patch(call_ea: int, target_ea: int):
        JMP_SIZE = 5
        rel_offset = (target_ea - (call_ea + JMP_SIZE)) & 0xFFFFFFFF
        rel_offset_slice = rel_offset.to_bytes(4, byteorder='little')
        jmp_instr = b'\xE9' + rel_offset_slice
        #-----------------------------------------------------------------------
        d.jmppatchedbuffer[call_ea:call_ea+JMP_SIZE] = jmp_instr
    for call_dispatch_ea, dispatch_target_ea in d.dispatchers_to_target.items():
        _apply_call_to_jmp_patch(call_dispatch_ea, dispatch_target_ea)
    d.mdp = x86Decoder(d.jmppatchedbuffer)
    #---------------------------------------------------------------------------
    d.log.info("Completed.")

#------------------------------------------------------------------------------
def _recover_all_dispatchers_via_emu(
    d: ProtectedInput64
):
    """Recover all of the dispatcher functions by matching their call location
    to their intended target. This is done in the following manner:
      1. identify all potential call locations in the protected input
      2. verify which of those locations are  dispatcher functions
      3. emulate the potential dispatchers to both, verify them and obtain
         their intended target

    This will be used as part of rebuilding the original control flow. Either:
      - `call dispatcher` -> `jmp dispatch_target`
      - `call dispatcher` ->  relocated target instruction
    """
    #---------------------------------------------------------------------------
    def _brute_find_all_calls(
        imgbuffer: bytes,
        data_section_rva: int
    ) -> list[int]:
        """ Brute-force byte-signature search the provided image buffer for all
        potential near relative call (`e8` only) instructions.
        """
        CALL_BYTE            = bytes([0xe8])
        start_index          = 0
        call_locs: list[int] = []
        #----------------------------------------------------------------------
        MAX_LENGTH = min(len(imgbuffer), data_section_rva)
        while start_index < MAX_LENGTH:
            curr_index = imgbuffer.find(CALL_BYTE, start_index)
            if curr_index == -1: break
            call_locs.append(curr_index)
            start_index = curr_index + 1
        return call_locs
    #---------------------------------------------------------------------------
    # Exceptions should be exclusive to failed decoding somewhere at `call_off`,
    # which is fine to it ignore but @TODO: add logging capacity nonetheless
    calls = _brute_find_all_calls(d.imgbuffer, d.DATA_SECTION_EA)
    potential_dispatchers: list[int] = []
    for call_off in calls:
        try:
            if _verify_dispatcher_pushfq(d, call_off):
                potential_dispatchers.append(call_off)
        except Exception as _:
            continue
    d.log.info(
        f"Found {len(potential_dispatchers)} potential_dispatchers\n"
        "\tVerifying further via emulation")
    #---------------------------------------------------------------------------
    # Emulate the dispatchers to obtain their target instruction
    from helpers.emu64 import EmulateIntel64
    emu = EmulateIntel64()
    emu.map_image(bytes(d.imgbuffer))
    emu.map_teb()
    snapshot = emu.context_save()
    #---------------------------------------------------------------------------
    LOG_INSTR: bool = False
    MAX_DISPATCHER_RANGE = 45 # dummy range, more than enough for any dispatcher
    #---------------------------------------------------------------------------
    # @TODO: add verifiers. Exceptions should only hit FPs that are mixed with
    #        regular ones. Maybe add logging to spot those cases.
    for call_dispatch_ea in potential_dispatchers:
        emu.context_restore(snapshot)
        emu.pc = call_dispatch_ea
        try:
            for _ in range(MAX_DISPATCHER_RANGE):
                emu.stepi()
                instr = next(emu.dis.disasm(emu.mem[emu.pc:emu.pc+15], emu.pc))
                if LOG_INSTR: d.log.info(f"\t{instr}")
                if x86.X86_GRP_RET in instr.groups:
                    next_pc = emu.parse_u64(emu.rsp)
                    if next_pc > len(d.imgbuffer):
                        # @TODO: obfuscator bug?
                        # [ShadowDeobf::WARNING]: broken instr dispatcher?? 15a70cd
                        pass
                        #d.log.warning(f"Maybe a broken dispatcher?? {next_pc:x}")
                    #-----------------------------------------------------------
                    d.dispatchers_to_target[call_dispatch_ea] = next_pc
                    d.dispatcher_locs.append(call_dispatch_ea)
                    break
        except Exception as _:
            continue
    d.log.info(f"Recovered {len(d.dispatcher_locs)} verified dispatchers")

#------------------------------------------------------------------------------
def _verify_dispatcher_pushfq(
    d: ProtectedInput64,
    call_offset: int
) -> bool:
    """Verifies instruction dispatchers by identifying their pushfq-popfq
    instruction sequences. Should be more than robust enough, if not can add
    the encoded offset fetch at the call's return address but given this will
    always be ran against the obfuscated state which protects every function,
    we can guarantee a lot with very little.

    This implements a raw disassembly pass that detects the guaranteed encoded
    offset decoding and ignoring any instruction-dispatcher-specific mutations
    that exist. The mutations can and do differ between samples and are prolly
    randomly selected form a set that obfuscator has.

    There can be no call instructions within a dispatcher.

    Dispatcher Mutations:
        .text:180010315 push    rdi
        .text:180010316 jp      loc_180004F7A
        .text:18001031C jnp     loc_180004F7A

        .text:180002549 mov     rsi, rsi
        .text:18000254C xchg    rsi, [rsp]
        .text:180002550 jmp     loc_1800039CA

        .text:1800028DA xchg    r15, [rsp]
        .text:1800028DE jmp     loc_1800114BC

        .text:180010A02 mov     cl, cl
        .text:180010A04 xchg    rdx, [rsp]
        .text:180010A08 jmp     loc_18000B310

    0001DBF  pushfq                       ; legitimate instruction
    0001DC0  jb      loc_5D29F            ; lol OP
    0001DC6  xchg    bx, bx               ; lol OP
    0001DC9  jnb     loc_5D29F            ; lol OP
    ----------------------------------------------------------------------
    005D29F  xor     rsi, 35FCF022h       ; legitimate instruction
    005D2A6  ja      loc_6D01             ; lol OP
    005D2AC  xchg    al, al               ; lol OP
    005D2AE  jbe     loc_6D01             ; lol OP
    ----------------------------------------------------------------------
    0006D01  sub     [rsp+10h], rsi       ; legitimate instruction
    0006D06  jo      loc_45D18            ; lol OP
    0006D0C  mov     dl, dl               ; lol OP
    0006D0E  jno     loc_45D18            ; lol OP
    ----------------------------------------------------------------------
    0045D18  popfq                        ; legitimate instruction
    0045D19  jg      loc_19D28            ; lol OP
    0045D1F  mov     r11, r11             ; lol OP
    0045D22  jle     loc_19D28            ; lol OP

    """
    call_instr = d.md.decode(call_offset)
    if not call_instr.is_call(): return False
    target_ea = call_instr.get_op1_imm()

    if target_ea not in range(0, len(d.imgbuffer)): return False

    pushfq_hit = False
    MAX_SCAN_RANGE  = 15
    curr_ea = target_ea

    count: int = 0
    while count < MAX_SCAN_RANGE:
        try:
            instr: x86Instr = d.md.decode(curr_ea)
        except Exception as _:
            return False

        if pushfq_hit and instr.is_popfq():
            return True

        if instr.is_pushfq():
            pushfq_hit = True
            count = 0
            curr_ea = instr.ea + instr.size
            continue

        if (
            x86.X86_GRP_RET in instr.groups or
            x86.X86_GRP_CALL in instr.groups or
            x86.X86_GRP_PRIVILEGE in instr.groups or
            instr.is_jmp() and (instr.is_op1_reg or instr.is_op1_mem)
        ):
            return False

        if instr.is_jcc() or instr.is_jmp():
            curr_ea = instr.get_op1_imm()
        else:
            curr_ea = instr.ea + instr.size

        count += 1

    return False
