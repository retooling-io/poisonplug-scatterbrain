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
#-------------------------------------------------------------------------------

"""Generates the deobfuscated, final output image for each mode of protection.

Generating an deobfuscated output image is split into two stages:
  1. building the output image template
    - peutils
    - rebuilding the original import table
  2. generating all relocations in the output and applying fixups
    - global reloc template and information
    - fixups

Given that there are 3 distinct modes of operation that the obfuscator employs
there are subtle differences in how stage 1 is implemented. Those differences
are implemented in the `pefile_utils.py` file.
"""
from recover.recover_core import (
    ProtectionType,
    ProtectedInput64,
    RecoveredInstr,
    RecoveredFunc,
    x86,
    struct
)
import helpers.pefile_utils as peutils

def rebuild_output(
    d: ProtectedInput64,
    preserve_original_imports: bool = False,
    LOG: bool=False
):
    """Build the final deobfuscated output based on the mode of protection.

    For HEADERLESS and FULL, given how we generate the output template and the
    how  the protection works, can always use the start of the .text section
    (0x1000) for the code region. For SELECTIVE, this will not be the case.
    The user needs to know the protected function upfront and specify it.

    """
    assert len(d.cfg.items()) != 0
    d.log.info("Initiating rebuild of deobfuscated binary result")

    func_rva: int = 0x1000
    match d.protection_type:
        case ProtectionType.HEADERLESS:
            (
                output_pe,           # pefile
                d.import_to_rva_map  # dict[ApiName, RVA]
            ) = peutils.build_from_headerless_image_with_imports(d.jmppatchedbuffer,
                                                                 d.DATA_SECTION_EA,
                                                                 d.DATA_SECTION_SIZE,
                                                                 d.imp_dict_builder)
            d.newimgbuffer = output_pe.__data__

        case ProtectionType.SELECTIVE:
            assert d.selective_func_rva != -1
            (
                output_pe,            # pefile.PE  output binary full template
                d.import_to_rva_map   # dict[ApiName, RVA]
            ) = peutils.build_memory_image_with_imports(d.pe,
                                                        d.imp_dict_builder)
            d.newimgbuffer = output_pe.__data__
            #-------------------------------------------------------------------
            # find end region of the protected function and clear the region
            END_MARKER = bytes.fromhex("CC CC CC CC 66 66 0F 1F 84 00 00 00 00 00")
            start = d.selective_func_rva
            found = d.newimgbuffer.find(END_MARKER, start)
            if found == -1:
                raise ValueError(f"failed to find END_MARKER for {start:x}")
            end  = found + len(END_MARKER)
            d.newimgbuffer[start:end] = bytearray(end-start)
            #-------------------------------------------------------------------
            func_rva = d.selective_func_rva

        case ProtectionType.FULL:
            (
                output_pe,            # pefile.PE  output binary full template
                d.import_to_rva_map   # dict[ApiName, RVA]
            ) = peutils.build_memory_image_with_imports(d.pe,
                                                        d.imp_dict_builder,
                                                        clear_text=True)
            d.newimgbuffer = output_pe.__data__
    #---------------------------------------------------------------------------
    d.log.info("Successfully completed rebuilt container for deobfuscated binary")
    Relocation.build_relocations(
        d,
        func_rva,
        preserve_original_imports)
    d.log.info("Successfully created functional deobfuscated binary output")

#-------------------------------------------------------------------------------
def align_to_16_byte_boundary(value: int) -> int: return (value + 15) & ~15

class Relocation: # just a namespace

    @staticmethod
    def build_relocations( #@TODO: rename to `build_relocs_and_final_code_segment`
        d: ProtectedInput64,
        starting_off:int=0x1000,
        preserve_original_imports: bool=False
    ):
        """This routine is responsible for building the new code segment for the
        debofuscated binary and applying all relocations to it.

        It is responsible for building out the `global_relocs` map, which uses
        a unique tuple key per-instruction to lookup its relocated address. The
        tuple is composed of the following:
          - `func_ea`:     starting address of function an instruction is a
                           part of (it's all functions at the end of the day)
          - `instr_ea`:    original instruction address
          - `is_boundary`: is the instruction is a synthetic one that we
                           introduced to build function boundaries (normalization).
                           We have to track these as they have no actual original
                           address (they're synthetic) and this needs to be
                           accounted for during the relocation e.g. it will
                           only have a relocation address.

        After the new code segment is build alongside the global relocs map,
        fixups are applied to account for every relevant memory reference.

        The code section (.text) is assumed to be at  0x1000 given how we build
        the output template. SELECTIVE mode will have `starting_off` specific
        to the original starting address of the selected function that was
        protected. `preserve_original_imports also applies to SELECTIVE mode
        as it will contain a legitimate import table separate from the
        protected one.
        """
        #-----------------------------------------------------------------------
        # build the new relocs first
        d.log.info(f"Starting relocation rebuild given starting offset of {starting_off:x}")
        curr_off = starting_off
        func_ea: int; rfn: RecoveredFunc
        for func_ea, rfn in d.cfg.items():
            rfn.reloc_ea = curr_off                                # relocated start ea
            d.global_relocs[(func_ea, func_ea, False)] = curr_off  # map in global lookup
            #-------------------------------------------------------------------
            r: RecoveredInstr
            for r in rfn.normalized_flow:
                d.global_relocs[(
                    func_ea,              # function instr is a part of
                    r.instr.ea,           # original instr location
                    r.is_boundary_jmp     # identifies whether instr is synthetic
                )] = curr_off
                r.reloc_ea = curr_off     # relocated instr ea
                #---------------------------------------------------------------
                ops = r.updated_bytes if r.updated_bytes else r.instr.bytes
                size = len(ops)
                #---------------------------------------------------------------
                d.newimgbuffer[curr_off:curr_off + size] = ops
                curr_off += size
            curr_off = align_to_16_byte_boundary(curr_off + 8)
        #-----------------------------------------------------------------------
        d.log.info("Applying fixups")
        for rfn in d.cfg.values(): # rfn: RecoveredFunc
            try:
                Relocation.apply_all_fixups_to_rfn(d, rfn)
            except Exception as e:
                d.log.error(f"Failed to apply fixups for function {rfn.func_start_ea:#08x}: {e}")
                continue
        
        d.log.info("Completed rebuild of relocations")

    @staticmethod
    def apply_all_fixups_to_rfn(
        d: ProtectedInput64,
        rfn: RecoveredFunc,
        LOG: bool=False
    ):
        """ Apply all known relocations to the new image, categorized in the
        following three formats:
            - control flow relocations
            - data flow relocations
            - import relocations
                - technically control flow as well, that are distinguished
                  on the fact that they're part of the obfuscator

        Because all uncovered samples were x64, relocation is exclusively limited
        to resolving the rip-relative addressing mode. It is the default mode in
        x64 binaries and virtually all data-referencing instructions (control flow
        instructions were already rip-relative since x86) will be in it.

        The signed displacement will always be the last 4 bytes outside of when
        an immediate operand exists alongside the displacement (the immediate
        granularity also plays into effect i.e., 8/16/32 (no 64-bit)):

            (c705d11d060001000000) mov dword ptr [rip+0x61dd1], 1
                C7 05 D1 1D 06 00 01 00 00 00
                :  :  :           :..IMM
                :  :  :..DISP
                :  :..MODRM
                :..OPCODE

            (48833d70e9030000) cmp qword ptr [rip + 0x3e970], 0
               48 83 3D 70 E9 03 00 00
               :  :  :  :           :..IMM
               :  :  :  :..DISP
               :  :  :..MODRM
               :  :..OPCODE
               :..REX

        """
        # @NOTE: assumes relocation already occured of the image buffer and each instruction
        #----------------------------------------------------------------------
        PACK_FIXUP = lambda fixup: bytearray(struct.pack("<I", fixup))
        CALC_FIXUP = lambda dest,size: (dest-(r.reloc_ea+size)) & 0xFFFFFFFF
        IS_IN_DATA = lambda dest: dest in d.data_range_rva

        def resolve_disp_fixup_and_apply(
            r: RecoveredInstr,
            dest: int
        ):
            """
            `reloc_ea` and `updated_bytes` are assumed to be valid
            The length of updated_bytes is only used in control flow
            """
            assert r.instr.disp_size == 4
            fixup = CALC_FIXUP(dest, r.instr.size)
            offset = r.instr.disp_offset
            r.updated_bytes[offset:offset+4] = PACK_FIXUP(fixup)

        def resolve_imm_fixup_and_apply(
            r: RecoveredInstr,
            reloc_dest: int,
        ):
            """call/jcc/jmp we handle ... add ...
            """
            assert (
                r.instr.is_call() or
                r.instr.is_jcc() or
                r.instr.is_jmp()
            )

            if r.instr.is_call():
                r.updated_bytes = d.ks.asm(
                    f'{r.instr.mnemonic} {reloc_dest:#08x}',
                    r.reloc_ea)[0]
            else:
                fixup = CALC_FIXUP(reloc_dest, len(r.updated_bytes))
                if r.instr.is_jmp():
                    assert len(r.updated_bytes) == 5 # placeholders
                    r.updated_bytes[1:5] = PACK_FIXUP(fixup)
                elif r.instr.is_jcc():
                    assert len(r.updated_bytes) == 6 # placeholders
                    r.updated_bytes[2:6] = PACK_FIXUP(fixup)

        def update_reloc_in_img(
            r: RecoveredInstr,
            tag: str
        ):
            """Assumes reloc_data to be valid

            """
            r.reloc_instr = d.md.decode_buffer(bytes(r.updated_bytes),
                                               r.reloc_ea)
            if len(r.updated_bytes) != r.reloc_instr.size:
                raise ValueError(
                    f'[Failed_{tag}_Reloc]: {r.func_start_ea:#08x}: '
                    f'{r.instr}, {r.reloc_instr}')
            d.newimgbuffer[r.reloc_ea:r.reloc_ea+r.reloc_instr.size] = r.updated_bytes
        """---------------------------------------------------------------------
        Imports
            d.imports:             dict[call/jmp addr]: RecoveredImport
            d.import_to_rva_map
        ---------------------------------------------------------------------"""
        r: RecoveredInstr
        for r in rfn.relocs_imports:
            if r.is_boundary_jmp:
                r.is_obf_import = False
                if LOG:
                    d.log.info(f'\tskipping synthetic jump that is linked to protected import {r}')
                continue

            r.updated_bytes = bytearray(r.instr.bytes)

            # @NOTE: `Empty` is for cases that are still not clear yet. They
            #        may not even be imports at all but basically they are
            #        a call+[rip+XXX] where the target is empty
            imp_entry = d.imports.get(r.instr.ea)
            if not imp_entry:
                if LOG:
                    d.log.info(f'[RelocImports] Could find imp entry for: {r}')
                continue
            elif imp_entry == 'Empty':
                continue

            # Get new RVA for this import
            new_rva = d.import_to_rva_map.get(imp_entry.api_name)
            if not new_rva:
                d.log.warning(f'[RelocImports] Could not find new RVA for: {imp_entry.api_name}')
                continue

            # Update the import entry
            imp_entry.new_rva = new_rva
            
            # Apply the fixup
            resolve_disp_fixup_and_apply(r, new_rva)
            update_reloc_in_img(r, "Import")

            if LOG:
                import_name = f'{imp_entry.dll_name}!{imp_entry.api_name}'
                d.log.info(f'RelocatedImport: {import_name:<40} {r.reloc_instr}')

        """---------------------------------------------------------------------
        ControlFlow

          - imports (ignore) identified here but already resolved
          - call
          - jcc/jmp
        update_bytes for is already set with the 6-byte variants with the
        displacement already padded with nops
        ---------------------------------------------------------------------"""
        for r in rfn.relocs_ctrlflow:
            if r.is_obf_import: continue

            dest = r.instr.get_op1_imm()
            reloc_dest = -1
            if r.instr.is_call():
                reloc_dest = d.global_relocs.get((dest, dest, False))
                if not reloc_dest:
                    raise ValueError(
                        f'[Call_Reloc] call: {r.instr} {dest:#08x} '
                        f'not relocated to {dest:08x}')
            else:
                reloc_dest = d.global_relocs.get((rfn.func_start_ea, dest, False))
                if not reloc_dest:
                    raise ValueError(
                        f'[JxxJmp_Reloc]: {r.func_start_ea:08x} '
                        f'{r.instr} {dest:#08x} {r.is_boundary_jmp}')
            assert(reloc_dest != -1)
            resolve_imm_fixup_and_apply(r, reloc_dest)
            update_reloc_in_img(r, tag="CtrlFlow")
            if LOG:
                d.log.info(f'RelocatedCtrlFlow: {r.reloc_instr}')

        """---------------------------------------------------------------------
        DataFlow

        We track known data relocation instructions to be completely certain of
        which instructions are used here. Any new ones are trivially detectable
        and straightforward to add in.

        Displacements are generally the last 4-bytes of the instruction but not
        guaranteed i.e., immediates.

        For .data references, we don't need to fix anything up as the .data
        section is left untouched during the deobfuscation and kept at the
        same starting location.

        @TODO: utilty helper to identify all relocation instruction types
         identify_all_reloc_instr_types(relocs_s)
         {'and', 'cmove', 'cmp', 'inc', 'lea', 'mov'}

        Resolving data flow fixups amounts to:
          1. Identifying the operand with the displacment
            - this will differ depending on the access
            - capstone's "detail" does the heavy lifting here (`disp`)
          2. Using the displacement to calculate full destination target
            - capstone again (we wrap is with `disp_dest`)
          3. "Fixup" the resolved destination
          4. Patch the fixup at the right offset within the instruction
            - capstone again alleviates any burden's here with `disp_offset`
        ---------------------------------------------------------------------"""
        KNOWN = [
            x86.X86_INS_INC, x86.X86_INS_LEA, x86.X86_INS_CMOVE,
            x86.X86_INS_MOV, x86.X86_INS_CMP, x86.X86_INS_AND
        ]
        for r in rfn.relocs_dataflow:
            if not r.instr.id in KNOWN:
                d.log.warning("[Missing dataflow instruction]: {r}")
                raise ValueError("Missing dataflow instruction")
            r.updated_bytes = bytearray(r.instr.bytes)

            instr_tag = r.instr.mnemonic.upper()
            reloc_dest = r.instr.disp_dest
            if not IS_IN_DATA(reloc_dest):
                reloc_dest = d.global_relocs.get((reloc_dest,reloc_dest,False))
                if not reloc_dest: # no func pointer or missed recovery
                    raise ValueError(
                        f"[ResolveFixup_{instr_tag}] "
                        f"{r.func_start_ea:#08x} "
                        f"{r.instr} {reloc_dest:#08x}"
                    )
            resolve_disp_fixup_and_apply(r, reloc_dest)
            update_reloc_in_img(r, "DataFlow")
            if LOG:
                d.log.info(f'RelocatedDataFlow: {r.reloc_instr}')

    @staticmethod
    def preserve_original_imports(
        d: ProtectedInput64
    ):
        for instr_ea, (api_name, instr_size) in d.imports_to_preserve.items():
            new_rva = d.import_to_rva_map.get(api_name)
            if not new_rva:
                d.log.info(f'Preserving import: {instr_ea:#x} {api_name}')
            fixup = (new_rva - (instr_ea + instr_size)) & 0xFFFFFFFF
            d.newimgbuffer[instr_ea+2:instr_ea+6] = (
                bytearray(struct.pack("<I", fixup))
            )