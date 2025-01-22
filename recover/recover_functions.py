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
#------------------------------------------------------------------------------

from recover.recover_core import (
    ProtectedInput64,
    RecoveredInstr, RecoveredFunc,
    x86
)
from recover.recover_cfg import recover_cfg_step as RECOVER_CFG_STEP

"""------------------------Recover Protected Function------------------------
Exposes the two core high-level CFG recovery functions:
    - recover_func
    - recover_recursive_in_full
"""
def recover_func(
    d: ProtectedInput64,
    func_start_ea: int
) -> RecoveredFunc:
    """Builds a RecoveredFunc via recovering its control flow & post processing
    the result to account for:
      - obfuscated imports
      - updates recovered branch instruction's target (see comment below))
      - classify instructions that would require relocation
      - TODO: anything else that pops up required to properly build the function

    Branching instructions, as residue from the DFS parse, do not have their
    targets verified to point to a recovered instruction. They can still point
    to a backbone instruction, i.e.,

    ; 0xc96e is a dispatcher instr that flows to 0xb657
      0x008b4c (e91d3e0000)  jmp 0xc96e    
      0x00b657 (8bd8)        mov ebx, eax  ; <==

    Once updated, it will look like the following (how it should be:)
      0x008b4c (e9062b0000)  jmp 0xb657
      0x00b657 (8bd8)        mov ebx, eax

    The relocation is specific to x64 (given nature of the samples) regarding
    data flow instructions (`rip in op_str`) as it assumes rip-relative is the
    addressing mode that's used (default for x64 binaries on Windows). Normally
    in x86, this addressing mode only applies to control flow transfer instructions
    (jcc/jmp/call etc.) but on x64, this includes data flow instructions (any
    instruction referencing a memory address within the 32-bit limit can be a
    candidate). With capstone under the hood, can simply check for `rip` in the
    `op_str` to identfy these types of instructions.
    """
    #---------------------------------------------------------------------------
    recovered:         list[RecoveredInstr]
    normalized_flow:   list[RecoveredInstr]
    ea_to_recovered:   dict[int, RecoveredInstr]
    obf_backbone:      dict[int, int]
    (
        _, # ignore func_start _ea, we take it as input
        recovered, normalized_flow,
        ea_to_recovered, obf_backbone
    ) = RECOVER_CFG_STEP(d, func_start_ea) # throws
    #---------------------------------------------------------------------------
    # Build relocs_ctrlflow and relocs_dataflow cache
    # @NOTE: `lea_refs` are only used as a quickie to find more code paths to
    #        explore. Works, but maybe revisit
    ctrlflow_relocs: list[RecoveredInstr] = []
    dataflow_relocs: list[RecoveredInstr] = []
    imports_relocs:  list[RecoveredInstr] = []
    lea_refs:        list[int]            = []

    r: RecoveredInstr
    for r in normalized_flow:
        # @TODO: d.import catches synthetic jmps that follow import calls,
        #        the`rip` check
        if r.instr.ea in d.imports and 'rip' in r.instr.op_str:
            r.is_obf_import = True
            imports_relocs.append(r)
        elif (
            r.instr.is_jcc() or
            (r.instr.is_jmp() and r.instr.is_op1_imm) or
            (r.instr.is_call() and r.instr.is_op1_imm)
        ):
            ctrlflow_relocs.append(r)
        elif (
            r.instr.is_call() and 'rip' in r.instr.op_str or
            r.instr.is_jmp() and 'rip' in r.instr.op_str
        ):
            # @TODO: need to skip this since how to account for it?
            d.log.info(f"Missed obfuscated import at {r.instr}")
            r.instr.is_obf_import = True
            d.imports[r.instr.ea] = "Empty"
            imports_relocs.append(r)
        elif r.instr.is_rip_relative:
            dataflow_relocs.append(r)
            if r.instr.is_lea():
                lea_target = r.instr.ea + r.instr.Op2.mem.disp + r.instr.size
                if lea_target >= d.DATA_SECTION_EA:
                    continue
                lea_refs.append(lea_target)
    #---------------------------------------------------------------------------
    """
    Use near jumps for all branching instructions during recovery to not
    be limited or get cute in cases where short jumps constitute the original
    instruction. The offsets are filled with nop placeholders that get
    populated during the relocation pass.
    """
    PAD = bytearray(b"\x90"*4)
    for r in ctrlflow_relocs:
        match r.instr.id:
            case x86.X86_INS_JMP: r.updated_bytes = bytearray(b"\xe9")     + PAD
            case x86.X86_INS_JA:  r.updated_bytes = bytearray(b"\x0f\x87") + PAD
            case x86.X86_INS_JAE: r.updated_bytes = bytearray(b"\x0f\x83") + PAD
            case x86.X86_INS_JB:  r.updated_bytes = bytearray(b"\x0f\x82") + PAD
            case x86.X86_INS_JBE: r.updated_bytes = bytearray(b"\x0f\x86") + PAD
            case x86.X86_INS_JE:  r.updated_bytes = bytearray(b"\x0f\x84") + PAD
            case x86.X86_INS_JG:  r.updated_bytes = bytearray(b"\x0f\x8f") + PAD
            case x86.X86_INS_JGE: r.updated_bytes = bytearray(b"\x0f\x8d") + PAD
            case x86.X86_INS_JL:  r.updated_bytes = bytearray(b"\x0f\x8c") + PAD
            case x86.X86_INS_JLE: r.updated_bytes = bytearray(b"\x0f\x8e") + PAD
            case x86.X86_INS_JNE: r.updated_bytes = bytearray(b"\x0f\x85") + PAD
            case x86.X86_INS_JNO: r.updated_bytes = bytearray(b"\x0f\x81") + PAD
            case x86.X86_INS_JNP: r.updated_bytes = bytearray(b"\x0f\x8b") + PAD
            case x86.X86_INS_JNS: r.updated_bytes = bytearray(b"\x0f\x89") + PAD
            case x86.X86_INS_JO:  r.updated_bytes = bytearray(b"\x0f\x80") + PAD
            case x86.X86_INS_JP:  r.updated_bytes = bytearray(b"\x0f\x8a") + PAD
            case x86.X86_INS_JS:  r.updated_bytes = bytearray(b"\x0f\x88") + PAD
    #---------------------------------------------------------------------------
    return RecoveredFunc(
        func_start_ea=func_start_ea,
        normalized_flow=normalized_flow,
        recovered=recovered,
        ea_to_recovered=ea_to_recovered,
        obf_backbone=obf_backbone,
        data_section_off=d.DATA_SECTION_EA,
        relocs_imports=imports_relocs,
        relocs_ctrlflow=ctrlflow_relocs,
        relocs_dataflow=dataflow_relocs,
        lea_refs=lea_refs
    )

RecoveredFunctions = dict[int,RecoveredFunc]

def recover_recursive_in_full(
    d: ProtectedInput64,
    func_start_ea: int=0x1000,
    LOG: bool = False
) -> RecoveredFunctions:
    """Starting from a given function start address, recursively recover the
    funcation and any subcalls.
    """
    #---------------------------------------------------------------------------
    func_to_explore: list[int]          = [func_start_ea]
    visited:         set[int]           = set()
    recovered_funcs: RecoveredFunctions = {}
    while func_to_explore:
        curr_fn_ea = func_to_explore.pop()
        if curr_fn_ea not in visited:
            try:
                rfn: RecoveredFunc = recover_func(d, curr_fn_ea)
                if LOG: rfn.pprint_normalized()
                #---------------------------------------------------------------
                visited.add(curr_fn_ea)
                recovered_funcs[curr_fn_ea] = rfn
                #---------------------------------------------------------------
                for sc in reversed(rfn.sub_calls):
                    if (
                        sc.is_call_reg() or
                        (sc.is_op1_mem and 'rip' not in sc.op_str)
                    ):
                        continue
                    if sc.is_op1_mem:
                        if not sc.ea in d.imports:
                            d.log.warning(f'missing sub call import (not in global imports): {sc}')
                        continue
                    #-----------------------------------------------------------
                    func_to_explore.append(sc.Op1.imm)
                    if LOG:
                        d.log.info(f'\tSubcall at: {func_to_explore[-1]:#08x} ({rfn})')
                #---------------------------------------------------------------
                for lea_ref in reversed(rfn.lea_refs):
                    func_to_explore.append(lea_ref)
                    if LOG:
                        d.log.info(f'\tLEA code reference: {func_to_explore[-1]:#08x} ({rfn})')
            except Exception as e:
                d.log.error(f'{e}')
                raise
    return recovered_funcs