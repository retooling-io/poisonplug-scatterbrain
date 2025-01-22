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

"""Core logic against the import protectiosn.

Exposes the following high-level API for recovery:
    - recover_imports

Note: current logic expects the ProtectedInput64 image to have specified
the `imp_decrypt_const` out-right. @TODO: eventually automate this but
it's trivial to get aorund now, albeit it requires manual effort. See
comment in recover_imp_crypt_const

"""
#-------------------------------------------------------------------------------
from recover.recover_core import (
    ProtectionType,
    ProtectedInput64,
    RecoveredImport,
    RecoveredFunc,
    x86Instr,
    struct
)

"""Import Protection

Exposes the logic required to resolve the imports which is centralized in the
following routine:
    - recover_imports_merge

"""
def recover_imports_merge(
    d: ProtectedInput64,
    LOG: bool=False
):
    """
    Handles the import resolution for both headerless and non-headerless cases.
    It identifies and processes potential import stubs, recovers import information,
    and updates the necessary data structures accordingly.
    """
    # set up functions and variables based on protection type
    if d.protection_type == ProtectionType.HEADERLESS:
        _resolve_imptbl(d)
        DECODE_INSTR      = d.md.decode
        GET_STUB_EA       = _get_stub_ea_headerless
        GET_DLL_API_NAMES = _get_dll_api_names_headerless
    else:
        DECODE_INSTR      = d.mdp.decode
        GET_STUB_EA       = _get_stub_ea_non_headerless
        GET_DLL_API_NAMES = _get_dll_api_names_non_headerless
    #---------------------------------------------------------------------------
    potential_stubs = _brute_find_impstubs(d)
    for p_ea in potential_stubs:
        try:
            instr = DECODE_INSTR(p_ea)
            if not (instr.is_call() or instr.is_jmp()): continue
            if 'rip' not in instr.op_str: continue
            #-------------------------------------------------------------------
            stub_ea, stub_id = GET_STUB_EA(d, instr)
            if stub_ea is None: continue
            #-------------------------------------------------------------------
            stub_rfn = recover_import_stub(d, stub_ea)
            if LOG: stub_rfn.pprint_normalized()
            #-------------------------------------------------------------------
            ref_instr = _extract_lea_ref_instr(stub_rfn)
            if ref_instr is None:
                # @TODO: should really throw here, never hit this case but still
                d.log.warning("Broken import assumption. Did not find 'lea' reference")
                raise ValueError("Broken assumptions with import stubs")
            #-------------------------------------------------------------------
            dll_name, api_name = GET_DLL_API_NAMES(d, ref_instr)
            #-------------------------------------------------------------------
            # call site is the only thing that's unique
            recovered_imp = RecoveredImport(
                instr, ref_instr,
                stub_id, stub_ea, stub_rfn,
                dll_name=dll_name,
                api_name=api_name
            )
            d.imports[instr.ea] = recovered_imp        # call/jmp size -> Imp
            d.imp_dict_builder[dll_name].add(api_name) # DllName -> ApiNAme
        except Exception:
            continue  # These shouldn't matter but maybe keep log anyway
    #---------------------------------------------------------------------------
    # Handle import preservation for SELECTIVE protection
    if d.protection_type == ProtectionType.SELECTIVE:
        _preserve_original_imports(d, potential_stubs)
    #---------------------------------------------------------------------------
    if len(d.imports) == 0:
        raise ValueError("Import recovery failed. Turn on debug utilities.")

def recover_imports(
    d: ProtectedInput64
):
    """Deprecated: just use merge unless testing individual new cases"""
    d.log.info("Starting import recovery pass for {mode} imports")
    mode = d.protection_type
    if mode == ProtectionType.HEADERLESS:
        recover_imports_headerless(d)
    else:
        recover_imports_as_dll(d)

def recover_import_stub(
    d: ProtectedInput64,
    stub_start_ea: int
) -> RecoveredFunc:
    from recover.recover_cfg import (
        recover_cfg_step as RECOVER_CFG_STEP,
        CFGResult
    )
    rslt: CFGResult  = RECOVER_CFG_STEP(d, stub_start_ea)
    return RecoveredFunc(
        func_start_ea=stub_start_ea,
        recovered=rslt.recovered_instrs,
        normalized_flow=rslt.normalized_flow,
        ea_to_recovered=rslt.ea_to_recovered,
        obf_backbone=rslt.obf_backbone,
        data_section_off=d.DATA_SECTION_EA
    )

def imp_crypt_str(
    d: ProtectedInput64,
    encrypted_bytes:bytes
) -> str:
    """Decrypts any import descriptor or API name used by the custom import
    protection. This routine is invoked from the import stub dispatcher
    function.

    @TODO: add logic to automatically recover the decrypt const
        - 0x6817FD83: F
        - 0x4328C142: T
    """
    # xtract initial value directly from the `encrypted_bytes`
    current_value = int.from_bytes(encrypted_bytes[:4], 'little')

    decrypted_bytes = bytearray()

    # max length, as specified by the initial algo
    MAX_LENGTH = 0x400
    for index in range(MAX_LENGTH):
        # @TODO: add a routine that extracts out the const through an obfuscated import
        calculated_value = (17 * current_value - d.imp_decrypt_const) & 0xFFFFFFFF
        value_bytes = calculated_value.to_bytes(4, 'little')

        # sum of the bytes, ensuring it's w/in byte range
        sum_value_bytes = sum(value_bytes) & 0xFF

        if index + 4 >= len(encrypted_bytes): break

        encrypted_byte = encrypted_bytes[index + 4]

        # decrypt && append
        decrypted_byte = encrypted_byte ^ sum_value_bytes
        decrypted_bytes.append(decrypted_byte)

        if encrypted_byte == sum_value_bytes: break

        # next cycle
        current_value = calculated_value
    return decrypted_bytes[:-1].decode("ascii")

"""---------------- (old) Recover Imports for Headerless----------------------"""
def recover_imports_headerless(
    d: ProtectedInput64
):
    """
    Handles the import resolution for cases where the import protection is
    present on headerless shadow executables. The primary difference is
    there is an import fixup table that needs to be used in order to match
    the import call/jmp sites to their respective dispatcher.

    Needs to resolve the import fixup table, which contains all the
    references to the obfuscated import components. This table only exists
    in HEADERLESS mode and contains the following:
        - encoded  DLL name
        - encoded  API name
        - impstubs location

    The first subroutine within the protected sample is responsible for
    preparing the imports correctly. This is added by the obfuscator and
    is conceptually part of the obfuscator's runtime.

    ImpTable example:
    ------------------------------------------------------------
    i.e., 66000 15 20 06 00  dd 62015h ; location of where it's ref'd
    66004 95 52 06 00  dd 65295h ; location of where the data is
    ------------------------------------------------------------
    66008 1D 20 06 00  dd 6201Dh ;
    6600C 84 3F 06 00  dd 63F84h ;
    ------------------------------------------------------------
    66010 4A 20 06 00  dd 6204Ah ;
    66014 00 20 06 00  dd 62000h ;
    ------------------------------------------------------------
    ... ... ...
    ------------------------------------------------------------

    The table is a global, fixed size array composed of two 32-bit offset
    slots. The first slot represents the location of where one of the
    import-specific data outlined earlier will be referenced from, the
    second slot is the location of where that same import-specific data
    actually resides.

    ```
    $_Loop_Resolve_ImpFixupTbl
    mov     ecx, [rdx+4]             ; fixup , either DLL, API, or ImpStub
    mov     eax, [rdx]               ; target ref loc that needs to be "fixed up"
    inc     ebp
    add     rcx, r13                 ; calculate fixup fully (r13 is shellcode base)
    add     rdx, 8                   ; next pair entry
    mov     [r13+rax+0], rcx         ; update the target ref loc w/ full fixup
    movsxd  rax, dword ptr [rsi+18h] ; fetch imptbl total size, in bytes
    shr     rax, 3                   ; account for size as pair-entry
    cmp     ebp, eax                 ; checkif if imptbl exhausted
    jl      $_Loop_Resolve_ImpTbl
    ```
    """
    LOG = False
    #---------------------------------------------------------------------------
    def _RESOLVE_IMPTBL():
        #-----------------------------------------------------------------------
        d.log.info("Resolving the imptable for HEADERLESS mode")
        assert d.DATA_SECTION_EA != -1
        assert d.IMPTBL_OFFSET   != -1
        assert d.IMPTBL_SIZE     != -1
        #-----------------------------------------------------------------------
        read32 = lambda index:  struct.unpack_from('<I', d.imgbuffer, index)[0]
        for i in range(
            d.DATA_SECTION_EA + d.IMPTBL_OFFSET,
            d.DATA_SECTION_EA + d.IMPTBL_OFFSET + d.IMPTBL_SIZE,
            8 # sizeof imp_tbl_entry_t
        ):
            location = read32(i); fixup = read32(i+4)
            d.imgbuffer[location:location+4] = struct.pack("<I", fixup)  # write
            d.imptbl[location] = fixup                                   # cache
        assert len(d.imptbl) == int(d.IMPTBL_SIZE / 8), (
            "failed to guarantee imptable size: {len(self.imptbl)}"
        )
        d.log.info("\tDone.")
    _RESOLVE_IMPTBL()
    #---------------------------------------------------------------------------
    potential_stubs = _brute_find_impstubs(d)
    for p_ea in potential_stubs:
        try:
            #-------------------------------------------------------------------
            # call, jmp
            instr = d.md.decode(p_ea)
            if not 'rip' in instr.op_str: continue
            #-------------------------------------------------------------------
            # Headerless variants require the use of this stub id as an index
            # into the fixed import table to reference their dispatcher targets
            stub_id = instr.get_call_target_mem()
            stub_ea = d.imptbl.get(stub_id)
            if not stub_ea:
                # @TODO: this will hit on bogus import stub, remove it via
                #        checking the call range
                d.log.warning(f"stub_id `{stub_id:#08x}` is not present"
                                 f" inside the import fixup table\n{instr}")
                continue
            #-------------------------------------------------------------------
            # recover the control flow for the associated import stub
            stub_rfn: RecoveredFunc = recover_import_stub(d, stub_ea)
            if LOG: stub_rfn.pp_normalized()
            #-------------------------------------------------------------------
            # extract the lef ref to the obf_imp_t for this import record
            ref_instr: x86Instr = None
            for i,r in enumerate(stub_rfn.recovered):
                if i >= 5:
                    d.log.warning(
                        "Broken IMPORT_ASSUMPTION. Did not "
                        "immediately find `lea` reference in "
                        f"{stub_rfn}")
                    input()
                #---------------------------------------------------------------
                if r.instr.is_lea() and 'rip' in r.instr.op_str:
                    ref_instr = r.instr
                    break
            #-------------------------------------------------------------------
            # obf_imp_t
            rva = ref_instr.ea + ref_instr.size + ref_instr.Op2.mem.disp
            dll_name_rva = int.from_bytes(d.imgbuffer[rva:rva+4], "little")
            api_name_rva = int.from_bytes(d.imgbuffer[rva+8:rva+12], "little")
            assert dll_name_rva != 0; assert api_name_rva != 0 # never actually hit this

            dll_name = imp_crypt_str(d,d.imgbuffer[dll_name_rva:dll_name_rva+50])
            api_name = imp_crypt_str(d,d.imgbuffer[api_name_rva:api_name_rva+50])

            #-------------------------------------------------------------------
            # call site is the only thing guaranteed to be unique
            recovered_imp = RecoveredImport(instr, ref_instr,
                                            stub_id, stub_ea, stub_rfn,
                                            dll_name=dll_name,
                                            api_name=api_name)
            d.imports[instr.ea] = recovered_imp        # call/jmp site -> RI
            d.imp_dict_builder[dll_name].add(api_name) # DllName -> ApiName
        except Exception as e:
            continue # these shouldn't matter but maybe keep log anyway?

    if len(d.imports) == 0:
        raise ValueError(f'Import recovery failed. Turn on dbg utilities.')

"""-------------- (old) Recover Imports for Non-Headerless--------------------"""
def recover_imports_as_dll(
    d: ProtectedInput64
):
    """
    Handles the import resolution for cases where the import protection is present for complete,
    on-disk shadow executables. There is no import fixup table to bother with, and the import
    call/jmp sites directly reference their respective stubs.
    """
    LOG = False

    #--------------------------------------------------------------------------
    # uses the patched imgbuffer as it's easier to walk through the backbone
    # when fetching the `obf_imp_t` for each stub
    potential_stubs: list[int] = _brute_find_impstubs(d)
    for p_rva in potential_stubs:
        try:
            #-------------------------------------------------------------------
            # call, jmp
            instr = d.mdp.decode(p_rva)
            if not (instr.is_call() or instr.is_jmp()): continue
            if not 'rip' in instr.op_str: continue # easiest way to do it w/ CS
            #-------------------------------------------------------------------
            stub_id = 0xffffff               # don't need one for dll cases
            stub_pp = instr.ea + instr.size + instr.Op1.mem.disp
            stub_ea = int.from_bytes(d.imgbuffer[stub_pp:stub_pp+8], "little")
            if stub_ea == 0:
                # some can be empty, not clear why as of now:
                #     mov   rcx, cs:qword_18001074A
                #     call  cs:qword_18001074A
                #     mov   ecx, dword ptr cs:qword_18001074A
                d.log.info(f'[ResolveImports] stub_ea is empty for {instr}')
                d.imports[instr.ea] = "Empty" # @TODO: change this to defaultdict
                continue
            #-------------------------------------------------------------------
            # stub pointers are fully resolved with their preferred imgbase,
            # simply work w/ their RVAs
            base = d.pe.OPTIONAL_HEADER.ImageBase
            stub_ea -= base
            stub_rfn = recover_import_stub(d, stub_ea)
            if LOG: stub_rfn.pprint_normalized()
            #-------------------------------------------------------------------
            # extract the lef ref to the obf_imp_t for this import record
            ref_instr: x86Instr = None
            for i,r in enumerate(stub_rfn.recovered):
                if i >= 5:
                    d.log.warning("Broken IMPORT_ASSUMPTION. Did not "
                                     "immediately find `lea` reference in "
                                     f"{stub_rfn}")
                    input()
                if r.instr.is_lea() and 'rip' in r.instr.op_str:
                    ref_instr = r.instr
                    break
            #-------------------------------------------------------------------
            # obf_imp_t
            rva = ref_instr.ea+ref_instr.size+ref_instr.Op2.mem.disp
            ea1 = int.from_bytes(d.imgbuffer[rva:rva+8], "little")
            ea2 = int.from_bytes(d.imgbuffer[rva+8:rva+16], "little")
            assert ea1 != 0; assert ea2 != 0

            # calcualte the rvas and extract the obf_imp_t contents
            dll_name_rva = (ea1-base) & 0xFFFFFFFF; api_name_rva = (ea2-base) & 0xFFFFFFFF
            dll_name = imp_crypt_str(d,d.imgbuffer[dll_name_rva:dll_name_rva+50])
            api_name = imp_crypt_str(d,d.imgbuffer[api_name_rva:api_name_rva+50])
            #-------------------------------------------------------------------
            # call site is the only thing that's unique
            recovered_imp = RecoveredImport(instr, ref_instr,
                                            stub_id, stub_ea, stub_rfn,
                                            dll_name=dll_name,
                                            api_name=api_name)
            d.imports[instr.ea] = recovered_imp        # call/jmp site -> RI
            d.imp_dict_builder[dll_name].add(api_name) # DllName -> ApiName
            #-------------------------------------------------------------------
        except Exception as _:
            continue # these shouldn't matter, but @TODO log
    if len(d.imports) == 0:
        raise ValueError(f"Import recovery failed. Turn on dbg utilities.")
    #-----------------------------------------------------------------------
    # in cases where only selected functions are protected, need to preserve the
    # original imports
    #
    # build a map of all import locations -> dll,api
    if d.protection_type == ProtectionType.SELECTIVE:
        imports_to_preserve: dict[int,tuple] = {}
        for desc_entry in d.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in desc_entry.imports:
                imports_to_preserve[imp.address] = desc_entry.dll.decode(),imp.name.decode()

        imgbase = d.pe.OPTIONAL_HEADER.ImageBase
        for rva in potential_stubs:
            if rva in d.imports: continue # protected stubs

            instr = d.mdp.decode(rva)
            if not (instr.is_call() or instr.is_jmp()): continue # call, jmp (misses leas, etc.)
            if not 'rip' in instr.op_str:               continue

            target = imgbase + (instr.ea + instr.size + instr.Op1.mem.disp)
            try:
                dll_name, api_name = imports_to_preserve[target]
                d.imp_dict_builder[dll_name].add(api_name)     # DllName -> ApiName
                d.imports_to_preserve[instr.ea] = api_name, instr.size
                print(f'Preserving: {dll_name}: {api_name}')
            except Exception as e:
                print(f'\tMissed import: {instr}')

"""---------------------------------Helpers----------------------------------"""
def _brute_find_impstubs(
    d: ProtectedInput64
) -> list[int]:
    """ Internal routine that implements a brute-force scanner to recover all
    possible import calls within a given imgbuffer by byte-signature scan.

    Post-processing is done afterwards to fully ensure these are valid.
    """
    patterns = [bytes.fromhex('FF15'), bytes.fromhex('FF25')]
    pattern_locs: list[int] = []
    # only scanning known code segment
    max_length = min(len(d.imgbuffer), d.DATA_SECTION_EA)
    for pattern in patterns:
        start_index = 0
        while start_index < max_length:
            curr_index = d.imgbuffer.find(pattern, start_index)
            if curr_index == -1 or curr_index >= max_length: # sanity
                break
            # @NOTE: abs indirect offset can exceed rva of data section,
            #        don't need a hard check here
            offset = struct.unpack(
                "<I", d.imgbuffer[curr_index+2:curr_index+6])[0]
            if offset < len(d.imgbuffer):
                pattern_locs.append(curr_index)
            start_index = curr_index + len(pattern)
    return pattern_locs

def __verify_recovered_imports(
    d: ProtectedInput64
):
    """Import recovery verifiers

    The call sites to (what will be upon resolution) the import stubs should
    always have data there e.g.:
        call_rva: 0x1b109 -> 7ff7000435d5
        call_rva: 0x1b120 -> 7ff700002adf
        call_rva: 0x1b170 -> 7ff70002102f
        call_rva: 0x1b1a0 -> 7ff70002102f
        call_rva: 0x1b1b9 -> 7ff70002102f
        call_rva: 0x1b1d1 -> 7ff70002102f
        call_rva: 0x1bbe6 -> 7ff70005dc77
        call_rva: 0x1bcaf -> 7ff700051cf7

    There are seldom cases where it will point to nothing e.g.:
        R: <x86Instr> 0x038e2c (ff158af10200) call qword ptr [rip + 0x2f18a]

    """
    read64 = lambda v:  struct.unpack_from('<Q', d.imgbuffer, v)[0]
    #-----------------------------------------------------------------------
    for ea, imp in d.imports.items():
        target_rva = imp.call_instr.get_call_target_mem()
        value = read64(target_rva)
        if value == 0:
            print(f'Failed imp verification at {imp.call_instr.ea}')

def _resolve_imptbl(
    d: ProtectedInput64
):
    """Resolves the import fixup table for HEADERLESS mode.

    ImpTable example:
    ------------------------------------------------------------
    i.e., 66000 15 20 06 00  dd 62015h ; location of where it's ref'd
    66004 95 52 06 00  dd 65295h ; location of where the data is
    ------------------------------------------------------------
    66008 1D 20 06 00  dd 6201Dh ;
    6600C 84 3F 06 00  dd 63F84h ;
    ------------------------------------------------------------
    66010 4A 20 06 00  dd 6204Ah ;
    66014 00 20 06 00  dd 62000h ;
    ------------------------------------------------------------
    ... ... ...
    ------------------------------------------------------------
    The table is a global, fixed size array composed of two 32-bit offset
    slots. The first slot represents the location of where one of the
    import-specific data outlined earlier will be referenced from, the
    second slot is the location of where that same import-specific data
    actually resides.

    ```
    $_Loop_Resolve_ImpFixupTbl
    mov     ecx, [rdx+4]             ; fixup , either DLL, API, or ImpStub
    mov     eax, [rdx]               ; target ref loc that needs to be "fixed up"
    inc     ebp
    add     rcx, r13                 ; calculate fixup fully (r13 is shellcode base)
    add     rdx, 8                   ; next pair entry
    mov     [r13+rax+0], rcx         ; update the target ref loc w/ full fixup
    movsxd  rax, dword ptr [rsi+18h] ; fetch imptbl total size, in bytes
    shr     rax, 3                   ; account for size as pair-entry
    cmp     ebp, eax                 ; checkif if imptbl exhausted
    jl      $_Loop_Resolve_ImpTbl
    ```
    """
    d.log.info("Resolving the imptable for HEADERLESS mode")
    assert d.DATA_SECTION_EA != -1
    assert d.IMPTBL_OFFSET   != -1
    assert d.IMPTBL_SIZE     != -1
    #---------------------------------------------------------------------------
    read32 = lambda index: struct.unpack_from('<I', d.imgbuffer, index)[0]
    for i in range(
        d.DATA_SECTION_EA + d.IMPTBL_OFFSET,
        d.DATA_SECTION_EA + d.IMPTBL_OFFSET + d.IMPTBL_SIZE,
        8  # sizeof imp_tbl_entry_t
    ):
        location = read32(i); fixup = read32(i+4)
        d.imgbuffer[location:location+4] = struct.pack("<I", fixup)  # write
        d.imptbl[location] = fixup                                   # cache
    #---------------------------------------------------------------------------
    assert len(d.imptbl) == int(d.IMPTBL_SIZE / 8), (
        f"Failed to guarantee imptable size: {len(d.imptbl)}"
    )
    d.log.info("Done.")

def _get_stub_ea_headerless(
    d: ProtectedInput64,
    instr: x86Instr
):
    """Retrieves the stub address and stub ID for HEADERLESS protection type.
    Headerless variants require the use of this stub id as an index
    into the fixed import table to reference their dispatcher targets
    """
    assert instr.is_call() or instr.is_jmp()
    stub_id = instr.get_call_target_mem()
    stub_ea = d.imptbl.get(stub_id)
    if not stub_ea:
        # @TODO: this will hit on bogus import stub, remove it via
        #        checking the call range
        #d.log.warning(
        #    f"stub_id `{stub_id:#08x}` is not present"
        #    f" inside the import fixup table\n{instr}")
        return None, None
    return stub_ea, stub_id

def _get_stub_ea_non_headerless(
    d: ProtectedInput64,
    instr: x86Instr
):
    """Retrieves the stub address for non-HEADERLESS protection type.
    We don't require a stub id (the initial memory displacement that gets
    fixed up) as non-HEADERLESS types don't have to have their imports
    relocated.
    """
    assert instr.is_call() or instr.is_jmp()
    stub_id = 0xffffffff
    stub_loc = instr.get_call_target_mem()
    stub_ea = int.from_bytes(d.imgbuffer[stub_loc:stub_loc+8], 'little')
    if stub_ea == 0:
        # some can be empty, not clear why as of now:
        #     mov   rcx, cs:qword_18001074A
        #     call  cs:qword_18001074A
        #     mov   ecx, dword ptr cs:qword_18001074A
        #d.log.info(f'stub_ea is empty for {instr}')
        d.imports[instr.ea] = "Empty"       # @TODO: change this to defaultdict
        return None, None
    base = d.pe.OPTIONAL_HEADER.ImageBase
    stub_ea -= base
    return stub_ea, stub_id

def _extract_lea_ref_instr(
    stub_rfn: RecoveredImport
):
    """ Extracts the 'lea' instruction that references the `obf_imp_t`
        push rcx
        lea rcx, [rip+obf_imp_t]  <===
        push    rdx
        push    r8
        push    r9
        sub     rsp, 28h
        call    ObfImportResolver
        add     rsp, 28h
        pop     r9
        pop     r8
        pop     rdx
        pop     rcx
        jmp     rax
    """
    for i, r in enumerate(stub_rfn.recovered):
        # we assume the 'lea' instruction is within the first few instructions
        if i >= 5: return None
        if r.instr.is_lea() and 'rip' in r.instr.op_str: return r.instr
    return None

def _get_dll_api_names_headerless(
    d: ProtectedInput64,
    ref_instr: x86Instr
):
    """Extracts and decrypts the DLL and API names for HEADERLESS protection type.
    """
    rva = ref_instr.ea + ref_instr.size + ref_instr.Op2.mem.disp
    dll_name_rva = int.from_bytes(d.imgbuffer[rva:rva+4], "little")
    api_name_rva = int.from_bytes(d.imgbuffer[rva+8:rva+12], "little")
    assert dll_name_rva != 0; assert api_name_rva != 0
    #---------------------------------------------------------------------------
    dll_name = imp_crypt_str(d, d.imgbuffer[dll_name_rva:dll_name_rva + 50])
    api_name = imp_crypt_str(d, d.imgbuffer[api_name_rva:api_name_rva + 50])
    return dll_name, api_name

def _get_dll_api_names_non_headerless(
    d: ProtectedInput64,
    ref_instr: x86Instr
):
    """Extracts and decrypts the DLL and API names for non-HEADERLESS
    protection type.
    """
    rva = ref_instr.ea + ref_instr.size + ref_instr.Op2.mem.disp
    ea1 = int.from_bytes(d.imgbuffer[rva:rva+8], "little")
    ea2 = int.from_bytes(d.imgbuffer[rva+8:rva+16], "little")
    assert ea1 != 0; assert ea2 != 0
    #---------------------------------------------------------------------------
    base = d.pe.OPTIONAL_HEADER.ImageBase
    dll_name_rva = (ea1-base) & 0xFFFFFFFF
    api_name_rva = (ea2-base) & 0xFFFFFFFF
    #---------------------------------------------------------------------------
    dll_name = imp_crypt_str(d, d.imgbuffer[dll_name_rva:dll_name_rva + 50])
    api_name = imp_crypt_str(d, d.imgbuffer[api_name_rva:api_name_rva + 50])
    return dll_name, api_name

def _preserve_original_imports(
    d: ProtectedInput64,
    potential_stubs
):
    """
    Preserves original imports in cases where only selected functions are protected.
    """
    imports_to_preserve = {}
    for desc_entry in d.pe.DIRECTORY_ENTRY_IMPORT:
        for imp in desc_entry.imports:
            imports_to_preserve[imp.address] = desc_entry.dll.decode(), imp.name.decode()

    imgbase = d.pe.OPTIONAL_HEADER.ImageBase
    for rva in potential_stubs:
        if rva in d.imports:
            continue  # Protected stubs
        instr = d.mdp.decode(rva)
        if not (instr.is_call() or instr.is_jmp()):
            continue  # Skip if not call or jmp
        if 'rip' not in instr.op_str:
            continue

        target = imgbase + (instr.ea + instr.size + instr.Op1.mem.disp)
        try:
            dll_name, api_name = imports_to_preserve[target]
            d.imp_dict_builder[dll_name].add(api_name)
            d.imports_to_preserve[instr.ea] = api_name, instr.size
            d.log.info(f'Preserving: {dll_name}: {api_name}')
        except Exception:
            d.log.warning(f'\tMissed import: {instr}')

# @TODO: wip
def recover_imp_crypt_const():
    """This is a TODO mainly out of lazyness and it's simpler to do the
    following:
        - pick a `stub_ea`
        - recover its cfg for it recursively
        - rebuild it and dump it out
    This rebuild a new binary with the core of the import protection
    only, can be loaded into IDA and identified. This is a true
    cavemen method until something like below can be done:
        - pick a `stub_ea`
        - emulate up to the decryption (fingerprint it)
        - auto extract it
        - or maybe just brute force it

    The import decryption can also be emulated although it would
    be pretty costly and the imp const can be ignored.

    e.g.,
        imp_const_test: RecoveredImport  = next(iter(p1.imports.values()))
        assert imp_const_test.stub_ea != 0xFFFFFFFF
        p1.cfg = recover_recursive_in_full(p1,imp_const_test.stub_ea)
        rebuild_output(p1)
        p1.dump_newimgbuffer_to_disk("c:/tmp/imp_tests.dll")
    """
    pass

