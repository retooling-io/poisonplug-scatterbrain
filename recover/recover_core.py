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

"""Represents all the data that encapsualtes the core of the recovery.

The core data types:
- `ProtectedInput64`:
    - the obfuscated input image  to operate on.
    - all transformations are applied to it.
- `RecoveredInstr`:
    - 1st core primitive of recovery, which encapsualtes a recovered instruction
      from the obfuscator
- `RecoveredFunc`:
    - 2nd core primitive of recovery, which encapsualtes a recovered function
      from the obfuscator
    - It is an aggregate of `RecoveredInstr`s
- `RecoveredImport`:
    - 3rd core primitive or recovery, encapsulating a recovered import from the
      obfuscator

@TODO: maybe a `recover_utils` scratch space for scratching?

Deps:
  pefile
  capstone
  keystone
  ucutils (unicorn)
"""
__author__ = "inino@google.com"
# -----------------------------------------------------------------------------
from dataclasses import dataclass, field
from enum import Enum
from helpers.x86disasm import x86, x86Instr
# -----------------------------------------------------------------------------
class ProtectionType(Enum):
    HEADERLESS = 1  # missing header information (so far, all final payload files)
    FULL       = 2  # input if fully protected
    SELECTIVE  = 3  # selected function(s) mixed with unprotected code

# -----------------------------------------------------------------------------
@dataclass
class RecoveredInstr:
    """
    The basic primitive for recovery. It represents a recovered instruction from
    the original, protected binary. It will always be associated with a/its
    respective recovered function.

    :func_start_ea:   ref to the parent function the instr is associated with
    :instr:           original, recovered instruction at its original location
    :reloc_instr:     original instruction, at its new, relocated address
    :reloc_ea:        the relocated ea for the instruction (in new image)
    :linear_ea:       the linear ea, after a CFG lineraization (normalization) pass
    :is_obf_import:   ids whether the instr is an obf call/jmp import instr
    :is_boundary_jmp: ids synthetic jmps added to the cfg recovery. These
                      need to be distinguished when relocating the instruction
    :updated_bytes:   the underlying operands that represent an instr can/will
                      be modifed during relocation and certain parts of the
                      deobfuscation.. Keep original and updated bytes separate

    NEW_ADDITIONS (still in progress)
    :prev_instr:        predecessor instructions
    :next_instr:        successor instructions
    """
    func_start_ea:   int           = -1
    type:            int|None      = None
    instr:           x86Instr|None = None
    reloc_instr:     x86Instr|None = None
    reloc_ea:        int           = 0xffffffff
    linear_ea:       int           = 0xffffffff
    is_boundary_jmp: bool          = False
    updated_bytes:   bytearray     = field(default_factory=bytearray)
    is_obf_import:   bool       = False

    def __str__(self):  return f"R: {self.instr}"
    __repr__ = __str__

@dataclass
class RecoveredFunc:
    """
    The second essential primitive for recovery. It represents the recovered
    function from the original, protected binary and constitutes an
    aggregate of recovered instructions (RecoveredInstr). Note, in this case
    it is explicitly an aggregate of instructions, not basic blocks. Extra
    passes can be added to include bb abstractions, if necessary.

    :func_start_ea    int: The original starting address of the function.
    :data_section_off int: Offset to `.data` section. Keeping it as part of
                           the function allows for easily distinguishing data
                           section cross-references.
    :recovered:       List[RecoveredInstr]      List of recovered instructions.
    :normalized_flow: List[RecoveredInstr]      List of instructions in normalized flow.
    :ea_to_recovered: Dict[int, RecoveredInstr] Map of original addresses to their recovered links.
    :obf_backbone:    Dict[int, int]            Backbone links particular to this function.
    :lea_refs:        List[int]                 References collected during LEA instructions processing.
    :size:            int                       Total size of the recovered instructions (computed after initialization).
    :sub_calls:       List[x86Instr]            List of instructions that are subroutine calls (computed after initialization).
    :reloc_ea:        int                       Relocated function start address.
    :relocs_imports:  List[RecoveredInstr]      Relocation info for imports.
    :relocs_ctrlflow: List[RecoveredInstr]      Relocation info for control flow instructions (jumps, calls).
    :relocs_dataflow: List[RecoveredInstr]      Relocation info for static data references.
    """

    func_start_ea:    int
    data_section_off: int = 0x62000

    recovered:       list[RecoveredInstr]     = field(default_factory=list)
    normalized_flow: list[RecoveredInstr]     = field(default_factory=list)
    ea_to_recovered: dict[int,RecoveredInstr] = field(default_factory=dict)
    obf_backbone:    dict[int,int]            = field(default_factory=dict)

    size: int = field(init=False)

    sub_calls:       list[x86Instr]           = field(init=False)
    lea_refs:        list[int]                = field(default_factory=list)

    reloc_ea: int = 0xFFFFFFFF
    relocs_imports:  list[RecoveredInstr]     = field(default_factory=list)
    relocs_ctrlflow: list[RecoveredInstr]     = field(default_factory=list)
    relocs_dataflow: list[RecoveredInstr]     = field(default_factory=list)

    def __post_init__(self):
        self.size = sum(len(r.instr.bytes) for r in self.recovered)
        self.sub_calls = [r.instr for r in self.recovered if r.instr.is_call()]

    def __str__(self):
        return f"<RecoveredFunction>: {self.func_start_ea:#08x}"
    __repr__ = __str__

    def pprint(self):
        line = "".join(["#", "-"*80])
        print(f"{line}\n[{self.func_start_ea:#08x}]")
        for r in self.recovered: print(r)
        line = "".join(["#", "- "*40]); print(line)
        print(f'  Imports:  ({len(self.relocs_imports)})')
        for r in self.relocs_imports: print(f'\t{r.instr}')
        print(f'  SubCalls: ({len(self.sub_calls)})')
        for sc in self.sub_calls: print(f'\t{sc}')
        print(f'  CtrlFlow: ({len(self.relocs_ctrlflow)})')
        for r in self.relocs_ctrlflow: print(f'\t{r.instr}')
        print(f'  DataFlow: ({len(self.relocs_dataflow)})')
        for r in self.relocs_dataflow: print(f'\t{r.instr}')

    def pprint_normalized(self):
        line = "".join(["#", "-"*80])
        print(f"{line}\n[{self.func_start_ea:#08x}]")
        for r in self.normalized_flow: print(r)
        line = "".join(["#", "- "*40]); print(line)
        print(f'  Imports:  ({len(self.relocs_imports)})')
        for r in self.relocs_imports: print(f'\t{r.instr}')
        print(f'  SubCalls: ({len(self.sub_calls)})')
        for sc in self.sub_calls: print(f'\t{sc}')
        print(f'  CtrlFlow: ({len(self.relocs_ctrlflow)})')
        for r in self.relocs_ctrlflow: print(f'\t{r.instr}')
        print(f'  DataFlow: ({len(self.relocs_dataflow)})')
        for r in self.relocs_dataflow: print(f'\t{r.instr}')

@dataclass
class RecoveredImport:
    """Encapsulates a recovered, protected import.

    =========================================================
    obf_imp_t struct ; (sizeof=0x18)
      +0x00    CryptDllNameRVA   dq ; rva to encrypted dll name
      +0x08    CryptAPINameRVA   dq ; rva to encrypted api name
      +0x10    ResolvedImportAPI dq ; final resolved address
      +0x18 obf_imp_t
    =========================================================

    ImportStub Dispatcher:
    ======================
    Recovering function at `0x005dbc`
    <x86Instr> 0x005dbc (e961140000)     jmp 0x7222
    <x86Instr> 0x007222 (51)             push rcx
    <x86Instr> 0x014b03 (488d0d9a470200) lea rcx, [rip+0x2479a] ; obf_imp_t
    <x86Instr> 0x0191b5 (e9a0deffff)     jmp 0x1705a
    #-------------------------------------------------------------------------------
    <x86Instr> 0x01705a (52)             push rdx
    <x86Instr> 0x0105b4 (4150)           push r8
    <x86Instr> 0x00f027 (4151)           push r9
    <x86Instr> 0x00e817 (4883ec28)       sub rsp, 0x28
    <x86Instr> 0x00a556 (e89fc5ffff)     call 0x6afa     ; ObfImportResolver
    <x86Instr> 0x006eaa (4883c428)       add rsp, 0x28
    <x86Instr> 0x006257 (4159)           pop r9
    <x86Instr> 0x0066d6 (4158)           pop r8
    <x86Instr> 0x01a3cb (5a)             pop rdx
    <x86Instr> 0x0067ab (59)             pop rcx
    <x86Instr> 0x006911 (ffe0)           jmp rax


    :call_instr:        call/jmp site for the import `call qw ptr [rip+0x308f2]`
    :ref_instr:         `lea` fetch inside the stub that ref's the `obf_imp_t`
    :stub_id:           used to lookup into the import fixup table, when present
    :stub_ea:           starting address for the import's impstub dispatcher
    :stub_rfn           the impstub's recovered, deobfuscated CFG. Note, not
                        required for recovery, but keeping it as reference
    :dll_name:          decrypted dll name the import is a part of
    :api_name:          decrypted import name
    :new_rva:           the new, relocated RVA to the added import thunk
    :reloc_call_instr:  the new relocated/updated call/jmp import call
    """
    call_instr:       x86Instr|None      = None
    ref_instr:        x86Instr|None      = None
    stub_id:          int                = 0xFFFFFFFF
    stub_ea:          int                = 0xFFFFFFFF
    stub_rfn:         RecoveredFunc|None = None
    dll_name:         str                = ''
    api_name:         str                = ''
    new_rva:          int|None           = -1
    reloc_call_instr: x86Instr|None      = None

    def __str__(self):
        """
         0x563C0: ImpStub:
           AdjustTokenPrivileges               (ADVAPI32.dll)
           CallSite: <0x563c0 [ff15a8c90000]: call qword ptr [rip + 0xc9a8]>
           LeaFetch: <0x2c45b [488d0d80940300]: lea rcx, [rip + 0x39480]>
           StubId:   0x062d6e
           StubEa:   0x02c45a,
        """
        if self.dll_name and self.api_name:
            return (
                    f'ImpStub:\n'
                    f'  {self.api_name:<35} ({self.dll_name})\n'
                    f'  CallSite: {self.call_instr}\n'
                    f'  LeaFetch: {self.ref_instr}\n'
                    f'  StubId:   {self.stub_id:#08x}\n'
                    f'  StubEa:   {self.stub_ea:#08x}'
            )
        else:
            return (
                    f'ImpStub:\n'
                    f'  CallSite: {self.call_instr}\n'
                    f'  LeaFetch: {self.ref_instr}\n'
                    f'  StubId:   {self.stub_id:#08x}\n'
                    f'  StubEa:   {self.stub_ea:#08x}'
            )
    __repr__ = __str__

"""--------------------------Protected Input Image---------------------------"""
from typing import Callable, TypeAlias
from collections import defaultdict, namedtuple
import struct
from pefile import PE
import keystone
from helpers.x86disasm import x86Decoder
from pathlib import Path, WindowsPath
#-------------------------------------------------------------------------------
@dataclass
class InputDetails:
    path:     WindowsPath
    md5:      str = ""
    sha256:   str = ""
#-------------------------------------------------------------------------------
import logging
_log = logging.getLogger("ProtectedImage64")
if not _log.handlers:
    c_handler = logging.StreamHandler()
    fmt = logging.Formatter('[%(name)s::%(levelname)s]: %(message)s')
    c_handler.setFormatter(fmt)
    _log.addHandler(c_handler)
    _log.setLevel(logging.DEBUG)

"""-------------------------Mutation Stepping Rules--------------------------"""
# @TODO: create the logic to easily find the rules by walking an address
#        in a controlled manner so the user can visually inspect every
#        step to identify a pattern to use
#
#  Or automate a "rule_verifier" that does a traversal with all sets of rules
#  and verifies which one are working and then generate a working rule set
#  out of it
#
#  @TODO: make these command line args so the user can specify them
#-------------------------------------------------------------------------------
# condition, action, result
class RuleResult(Enum):
    CONTINUE  = 1   # Continue to the next instruction in the traversal
    BREAK     = 2   # Break out of the traversal completely
    NEXT_RULE = 3   # Skip to the next rule

RuleHandler: TypeAlias = Callable[
    ["ProtectedInput64", "CFGStepState", "x86Instr"], RuleResult
]

class ProtectedInput64:
    """
    Input Image Info
    ----------------
    :filepath:          filepath of the input binary image blob or pefile
    :protection_type:   ids how the protection was applied
    :pe:                represents the input PE image when it is not headerless
    :imgbuffer:         main memory mapped buffer for the underlying image being processed
    :jmppatchedbuffer:  ^^ with the instruction dispatchers patched to JMPs
    :newimgbuffer:      final output buffer used to produce the deobfuscated output
    :IMPTBL_OFFSET:     (headerless-only) offset from start of data section to imp table
    :IMPTBL_SIZE:       (headerless-only )size of the imp table in data section
    :DATA_SECTION_EA    rva to the start of the data section (required primarily for headerless)
    :DATA_SECTION_SIZE  size of the data section
    :code_range_rva:    range of the .text section to do quick "in_range" look ups
    :data_range_rva:    range of the .data section to do quick "in_range" look ups

    Disassembler/Assembler Utils
    ----------------------------
    :md:  x86Decoder   disassembler over the intial memory-mapped input image
    :mdp: x86Decoder   disassembler over JMP patched image (instruction dispatchers)
    :ks:  keystone.Ks  keystone assembler to build instructions when required

    Obfuscator Properties:

    InstructionDispatcher
    ---------------------
    :dispatcher_locs:      array of all dispatcher call locations
    :dispatchers:          map of dispatcher call locations to target dest links
    :global_backbone_map:

    ImportProtection
    ----------------
    :imptbl:               (headerless-only) [location] -> fixup
    :imports:              map for each import call/jmp location to its RecoveredImport type
    :imports_to_preserve:  (selective-only) original imports not part of protection to preserve
    :imp_dict_builder:     import map for rebuilding the import table
    :import_to_rva_map:    mapping of import names to their new int_rva (produced by peutils, for output)

    FullRecovery
    ------------
    :global_relocs:        global lookup table for all relocated instructions that uses a tuple
                           (func_start_ea, instr_ea, is_jmp_boundary) as the key to id the
                           relocated ea for each recovered instruction
    :cfg:                  all recovered, normalized deobfuscated functions
    """

    def __init__(
        self,
        filepath: str,
        protection_type: ProtectionType,
        imp_decrypt_const: int,
        mutation_rules,
        selective_func_rva = -1,
        data_sec_rva: int = -1
    ):
        """
        :filepath:           filepath on disk to the protected input
        :protection_type:    specify the mode of protection
        :imp_decrypt_const:  the imports protection uses a custom crypt routine
                             that relies an a hardcode const that can vary.
                             Allow the user to specify it up front until we
                             don't suck anymore and get smarter here.
        :mutation_rules:     the mutation rules that guide the control flow
                             recovery. See RULE_HANDLER_XXX.
        :selective_func_rva: for ProtectionType.SELECTIVE, the rva of the
                             protected function. Needs to be specified when the
                             mode is SELECTIVE
        :data_sec_rva:       rva of the .data section. This was used initially
                             before more samples were obtained and only the
                             HEADERLESS mode was available. There is some added
                             logic that auto-detects this but can override it
                             here.

        The differences b/w the two inputs that concern us are the following:
            - data section offset/size
                - let the user manually specify or when it's a plugin, parse
                  explicitly for the `.data` section
                - plugins should also have a `reloc` section as well
            - obfsucated imports slightly differs
                - primarily related to relocs with imports and their stubs and
                  the existence of an import fixup table
        """
        """----------------------Input Image Properties----------------------"""
        self.log = _log
        self.input_info:        InputDetails = InputDetails(path=Path(filepath))
        self.filepath:          str          = filepath

        if (
            protection_type == ProtectionType.SELECTIVE and
            selective_func_rva == -1
        ):
            raise ValueError("Specify the rva for the protected function")
        self.protection_type:    ProtectionType               = protection_type
        self.selective_func_rva: int                          = selective_func_rva

        self.pe:                 PE|None                      = None
        self.imgbuffer:          bytearray                    = bytearray()
        self.jmppatchedbuffer:   bytearray                    = bytearray()
        self.newimgbuffer:       bytearray                    = bytearray()
        self.IMPTBL_OFFSET:      int                          = -1
        self.IMPTBL_SIZE:        int                          = -1
        self.DATA_SECTION_EA:    int                          = data_sec_rva
        self.DATA_SECTION_SIZE:  int                          = -1
        self.code_range_rva:     range|None                   = None
        self.data_range_rva:     range|None                   = None

        """----------------------Obfuscator Properties-----------------------"""
        self.mutation_rules: list[Callable[
            ["ProtectedInput64", "CFGStepState", "x86Instr"], "RuleResult"]
        ] = mutation_rules

        self.dispatcher_locs:       list[int]                 = []
        self.dispatchers_to_target: dict[int,int]             = {}
        self.global_backbone_map:   dict[int, int]            = {}

        self.imp_decrypt_const:     int                       = imp_decrypt_const
        self.imptbl:                dict[int,int]             = {}
        self.imports:               dict[int,RecoveredImport] = {}
        self.imports_to_preserve:   dict[int,tuple]           = {}
        self.imp_dict_builder                                 = defaultdict(set)
        self.import_to_rva_map:     dict[str,int]             = {}

        self.global_relocs:         dict[tuple,int]           = {}
        self.cfg:                   dict[int,RecoveredFunc]   = {}

        """-------------------------Initialize Input-------------------------"""
        self._initialize_image_input() # throws @TODO: maybe handle it here

        """----------------------Disassembly, Assembly-----------------------"""
        self.md:  x86Decoder = x86Decoder(bytes(self.imgbuffer))
        self.mdp: x86Decoder|None = None
        self.ks: keystone.Ks = keystone.Ks(
            keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        #@TODO: add struct read/write wrappers to imgbuffer/jmppatchedbuffer


    """-------------------------Input Initialization-------------------------"""
    def _initialize_image_input(self):
        """Process the input specified by the filepath. Current known inputs are
        of two distinct types:
            Legitimate PE binary
            Headerless PE binary (initially referred to as "shellcode")

        These vary initially on how they are processed.
            @TODO: add all the relevant details here
        """
        try:
            with open(self.input_info.path.absolute(), "rb") as file:
                self.imgbuffer = bytearray(file.read())

            from hashlib import md5 as MD5; from hashlib import sha256 as SHA256
            self.input_info.md5     = MD5(self.imgbuffer).hexdigest().upper()
            self.input_info.sha256  = SHA256(self.imgbuffer).hexdigest().upper()
            _log.info(
                f"processing input:\n"
                f"\tFilepath: {self.input_info.path}\n"
                f"\tBasename: {self.input_info.path.stem}\n"
                f"\tSHA256:   {self.input_info.sha256}\n"
                f"\tMD5:      {self.input_info.md5}\n"
                f"\tMode:     {self.protection_type}")

            if self.protection_type == ProtectionType.HEADERLESS:
                """
                scan for the 00 00 00 00 from the end of the buffer (CANNOT BE THE END)
                scan for 00 * 12
                
                0675D0 00 20 06 00  dd 62000h     ; START_OF_DATA_SECTION
                0675D4 00 40 00 00  dd 4000h      ; OFFSET_TO_IMPTABLE (from start of data section)
                0675D8 C0 15 00 00  dd 15C0h      ; SIZE OF IMPTABLE

                METADATA_CONFIG
                ---------------------------------------------------------
                00 00 00 00 ; buffer_t that contains the injected payload at runtime (empty at start)
                00 00 00 00
                00 00 00 00
                ---------------------------------------------------------
                BLOBS[]
                ---------------------------------------------------------
                00 00 00 00


                +0x00  084290 dd 0AD5E8E5Ah      Integrity MAC (naturally, will differ)
                +0x04  084294 dd 1189B0E4h
                +0x08  084298 dd 0AC9C36F3h
                +0x0C  08429C dd 135FB4F6h
                +0x10  0842A0 dd 48BBBDFEh
                +0x14  0842A4 dd 0BCF64F48h
                ---------------------------------------------------------
                +0x18  0842A8 dd 80000h         ; DATA_SECTION_RVA
                +0x1C  0842AC dd 3000h          ; IMPTABLE_OFFSET (from start of data section)
                +0x20  0842B0 dd 1290h          ; IMPTABLE_SIZE (in bytes)
                ---------------------------------------------------------
                Type: shadow_file_buffer_t (populated on headerless init)
                +0x24  0842B4 dd 0              ; memory allocation of initial loaded headerless payload
                +0x28  0842B8 dd 0              ; max size
                +0x2C  0842BC dd 0              ; size
                ---------------------------------------------------------
                First blob: 80, 0x974 (config in this case)
                +0x30  0842C0 dd 80000974h      ; CONFIG BLOB

                The end marker shouldn't be further than ~0x20 bytes from the end. It's a rough
                guess but should suffice. Also ignore scanning the salt.
                """
                read32 = lambda index:  struct.unpack_from('<I',
                    self.imgbuffer, index)[0]

                # @TODO: maybe do something more with this data out of the box
                BlobData = namedtuple('Blob', ['offset', 'id', 'size'])

                # end_offset -> 00 00 00 00 (END_MARKER)
                def _process_blobs(start_offset: int, end_offset: int):
                    curr_offset = start_offset
                    blobs: list[BlobData] = []

                    while curr_offset < end_offset:
                        blob_size = read32(curr_offset) & 0xFFFFFF
                        if blob_size == 0 or curr_offset + blob_size > end_offset:
                            raise ValueError("invalid blob size or corrupted blob structure")

                        id = (read32(curr_offset) & 0xFF000000) >> 24
                        blobs.append(BlobData(curr_offset, id, blob_size))

                        curr_offset += (blob_size+4)
                    return blobs

                END_BLOB_MARKER   = b"\x00"*4
                START_BLOB_MARKER = b"\x00"*12

                # ignore the last 4 bytes, the pattern can also not hit there
                # @NOTE: ^^ doesn't hold for case "F", maybe I chopped some bytes there?? But
                #        leaving it out for that reason
                imgsize = len(self.imgbuffer)
                end_marker = self.imgbuffer.rfind(END_BLOB_MARKER, imgsize-0x20, imgsize)
                if end_marker == -1: raise ValueError("failed to find blob end marker")

                start_marker = self.imgbuffer.rfind(START_BLOB_MARKER, 0, end_marker)
                if start_marker == -1: raise ValueError("failed to find blob start marker")

                # verify the scan and extract out the blobs as well
                blob_start_offset = start_marker + len(START_BLOB_MARKER)

                try:
                    blobs_info = _process_blobs(blob_start_offset, end_marker)
                    s = "\n".join(
                        f"\tblob {b.id:#04x} at {b.offset:#08x} with size {b.size:#04x}"
                        for b in blobs_info
                    )
                    _log.info(f'successfully recovered all known blob data:\n{s}')
                except ValueError as e:
                    raise ValueError(f'failed in recovering blobs: {e}')
                #--------------------------------------------------------------
                metadata_start_offset = start_marker - 12
                self.DATA_SECTION_EA   = read32(metadata_start_offset)
                self.DATA_SECTION_SIZE = len(self.imgbuffer)-self.DATA_SECTION_EA
                self.IMPTBL_OFFSET     = read32(metadata_start_offset+4)
                self.IMPTBL_SIZE       = read32(metadata_start_offset+8)
                self.code_range_rva    = range(0, self.DATA_SECTION_EA)
                self.data_range_rva    = range(
                    self.DATA_SECTION_EA,
                    self.DATA_SECTION_EA + self.DATA_SECTION_SIZE
                )
                #--------------------------------------------------------------
                _log.info(
                    "headerless variant metadata header recovered and verified:\n"
                    f"\t.data section RVA:  {self.DATA_SECTION_EA:#08x}\n"
                    f"\t.data section size: {self.DATA_SECTION_SIZE:#08x}\n"
                    f"\tImportTable offset: {self.IMPTBL_OFFSET:#08x} (from start of .data section)\n"
                    f"\tImportTable size:   {self.IMPTBL_SIZE:#08x} (in bytes)"
                )

            else:
                import helpers.pefile_utils as pu
                self.imgbuffer = pu.build_memory_image(PE(data=self.imgbuffer)) # tmp
                self.pe = PE(data=self.imgbuffer)
                #--------------------------------------------------------------
                # resolve the .data section
                assert self.DATA_SECTION_EA == -1
                _log.info("assuming a .data section (with that exact name) exits")
                for s in self.pe.sections:
                    if s.Name.startswith(b'.data'):
                        self.DATA_SECTION_EA   = s.VirtualAddress
                        self.DATA_SECTION_SIZE = s.Misc_VirtualSize
                        self.data_range_rva = range(
                            self.DATA_SECTION_EA,
                            self.DATA_SECTION_EA + self.DATA_SECTION_SIZE
                        )
                if self.DATA_SECTION_EA == -1:
                    raise ValueError("input binary does not contain a .data section")
                _log.info(f".data section at +{self.DATA_SECTION_EA:#08x}")
                #--------------------------------------------------------------
                # you know it
                code_sec = self.pe.sections[0]
                self.code_range_rva = range(
                    code_sec.VirtualAddress,
                    code_sec.VirtualAddress + code_sec.Misc_VirtualSize
                )
                #--------------------------------------------------------------
                #ethese should only exist in headerless mode
                assert self.IMPTBL_OFFSET == -1; assert self.IMPTBL_SIZE == -1

        except FileNotFoundError:
            _log.error(f"File {self.filepath} was not found."); raise
        except PermissionError:
            _log.error(f"Permission denied trying to read {self.filepath}."); raise
        except Exception as e:
            _log.error(f"Whoopsie daisy: {e}"); raise

    def dump_newimgbuffer_to_disk(
        self,
        filepath: str=""
    ):
        filepath = filepath if filepath != "" else (
            f"{self.input_info.path.parent}/" +
            f"{self.input_info.path.stem}"   +
            "--DEOBFUSCATED"                +
            f"{self.input_info.path.suffix}"
        )
        open(filepath, "wb").write(self.newimgbuffer)


"""-----------------------Mutation Rule Stepping Logic-----------------------"""
"""
Rules will be specific and rule order MATTERS
"""

def RULE_HANDLE_DISPATCHER_JMP_AND_STANDARD_JMPS(
    d: ProtectedInput64,
    s: 'CFGStepState',
    instr: x86Instr
) -> RuleResult:
    """Mandated rule that always needs to be ran first as it accounts for the
    core of the protection: instruction dispatchers.
    """
    if instr.is_jmp() and instr.ea in d.dispatcher_locs:
        jmp_dest = instr.get_op1_imm()
        s.obf_backbone[instr.ea] = jmp_dest
        s.to_explore.append(jmp_dest)
        return RuleResult.CONTINUE
    elif instr.is_jmp():
        rinstr = RecoveredInstr(func_start_ea=s.func_start_ea, instr=instr)
        s.recovered.append(rinstr)
        s.ea_to_recovered[instr.ea] = rinstr
        #----------------------------------------------------------------------
        if instr.is_op1_reg or instr.is_op1_mem:
            return RuleResult.CONTINUE
        jmp_dest = instr.get_op1_imm()
        s.to_explore.append(jmp_dest)
        return RuleResult.CONTINUE
    return RuleResult.NEXT_RULE

def RULE_HANDLE_TEST_OPAQUE_PREDICATE(
    d: ProtectedInput64,
    s: 'CFGStepState',
    instr: x86Instr
) -> RuleResult:
    def _verify_test_op():
        """
        Verify the test opaque predicate pattern via instruction pattern
        matching.

        @NOTE: it is assumed that dispatcher functions have been patched
               with their `jmp intended_target` instructions. Revisit
               this if not patching in the jmp but replacing with target
               It's also assumed that there won't be more than 1 back-2-back
               instruction jmp dispatchers in order
        """
        if not (
            instr.is_test() and       # always a `test` instr
            instr.is_op1_reg and      # first op always reg
            instr.is_op2_imm and      # 2nd op always an immediate
            instr.get_op2_imm() == 0  # the immediate is always -1
        ):
            return False,None
        next_instr = d.mdp.decode_next_insn_incl_jmp(instr)
        return (True,next_instr) if next_instr.is_jcc() else (False,None)
    #--------------------------------------------------------------------------
    is_backbone, following_instr = _verify_test_op()
    if is_backbone:
        link_instr = d.mdp.decode_next_insn(following_instr)
        s.obf_backbone[instr.ea] = link_instr.ea
        s.to_explore.append(link_instr.ea)
        return RuleResult.CONTINUE
    return RuleResult.NEXT_RULE

def RULE_HANDLE_BACK2BACK_JCC(
    d: ProtectedInput64,
    s: 'CFGStepState',
    instr: x86Instr
) -> RuleResult:
    def _verify_b2b_same_jcc():
        """
        Verify the protected conditionals pattern via instruction pattern
        matching.

        i.e.,
        seg000:471C4 0F 87 D2 4D FF FF  ja   loc_3BF9C
        seg000:471CA 0F 87 84 5F FE FF  ja   loc_2D154  <== bogus
        ------------------------------------------------------------
        seg000:004ED 0F 85 D2 94 00 00  jnz  loc_99C5
        seg000:004F3 0F 85 F3 1C 01 00  jnz  loc_121EC  <== bogus

        @NOTE: it is assumed that dispatcher functions have been patched
               with their `jmp intended_target` instructions. Revisit
               this if not patching in the jmp but replacing with target
        """
        if not instr.is_jcc(): return False,None
        next_instr = d.mdp.decode_next_insn_incl_jmp(instr)
        return (True,next_instr) if instr.id == next_instr.id else (False,None)
    #--------------------------------------------------------------------------
    is_backbone, following_instr = _verify_b2b_same_jcc()
    if is_backbone:
        s.recovered.append(
            RecoveredInstr(func_start_ea=s.func_start_ea, instr=instr)
        )
        s.ea_to_recovered[instr.ea] = s.recovered[-1]
        s.obf_backbone[following_instr.ea] = following_instr.ea+following_instr.size

        branch_dest = instr.get_op1_imm()
        s.to_explore.append(branch_dest)
        s.to_explore.append(following_instr.ea + following_instr.size)
        return RuleResult.CONTINUE
    return RuleResult.NEXT_RULE

def RULE_HANDLE_CMP_RSP_IMM(
    d: ProtectedInput64,
    s: 'CFGStepState',
    instr: x86Instr
) -> RuleResult:
    if (
        instr.is_cmp() and
        instr.is_op1_reg_rsp() and
        instr.is_op2_imm
    ):
        next_instr = d.mdp.decode_next_insn_incl_jmp(instr)
        assert next_instr.is_jcc()

        s.obf_backbone[instr.ea] = next_instr.ea + next_instr.size
        s.to_explore.append(next_instr.ea+next_instr.size)
        return RuleResult.CONTINUE
    return RuleResult.NEXT_RULE

def RULE_HANDLE_STANDARD_JCC(
    d: ProtectedInput64,
    s: 'CFGStepState',
    instr: x86Instr
) -> RuleResult:
    """Handle standard jcc cases
    """
    if instr.is_jcc():
        s.recovered.append(
            RecoveredInstr(func_start_ea=s.func_start_ea,instr=instr)
        )
        s.ea_to_recovered[instr.ea] = s.recovered[-1]
        s.to_explore.append(instr.get_op1_imm())    # branch target
        s.to_explore.append(instr.ea+instr.size)  # fallthrough instruction
        return RuleResult.CONTINUE
    return RuleResult.NEXT_RULE

def RULE_HANDLE_RET_INT3(
    d: ProtectedInput64,
    s: 'CFGStepState',
    instr: x86Instr
) -> RuleResult:
    if instr.is_ret() or instr.is_int3():
        s.recovered.append(
            RecoveredInstr(
                func_start_ea=s.func_start_ea,
                instr=instr)
        )
        s.ea_to_recovered[instr.ea] = s.recovered[-1]
        return RuleResult.CONTINUE
    return RuleResult.NEXT_RULE

RULE_SET_1 = [
    RULE_HANDLE_DISPATCHER_JMP_AND_STANDARD_JMPS,
    RULE_HANDLE_TEST_OPAQUE_PREDICATE,
    RULE_HANDLE_BACK2BACK_JCC,
    RULE_HANDLE_STANDARD_JCC,
    RULE_HANDLE_RET_INT3
]

RULE_SET_2 = [
    RULE_HANDLE_DISPATCHER_JMP_AND_STANDARD_JMPS,
    RULE_HANDLE_CMP_RSP_IMM,
    RULE_HANDLE_STANDARD_JCC,
    RULE_HANDLE_RET_INT3
]