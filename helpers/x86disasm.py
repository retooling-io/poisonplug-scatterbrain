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
# -----------------------------------------------------------------------------


"""Capstone x86 disassembler wrapper

Classes:
    x86Disasm:  disassembly engine
    x86Instr:   extended instruction
    x86Helpers: genreal x86-helpers

Usage:
    from x86disasm import x86Disasm, x86Instr

@TODO: create a utility tool (like `ZyidsInfo`) to be able to verify and
       inspect any instructions of interest standalone
"""
try:
    import capstone as cs
    import capstone.x86 as x86
except ImportError as e:
    print(f"Error: Required module not found. {e}")
    print("Make sure you have the 'capstone' library installed.")
    print("You can install it using: `pip install capstone`")
    exit(1)
# -----------------------------------------------------------------------------
def create_disasm_engine(is64=True) -> cs.Cs:
    """Create an intel capstone disassemble engine instance"""
    md = (
        cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64) if is64 else
        cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    )
    md.detail = True # we care about operand inspection by default
    return md

# -----------------------------------------------------------------------------
class x86Instr(cs.CsInsn):
    """Overloaded x86 `CsInsn` class for convenience to remove CS crudeness.
    Still under development.

    Original CS properties (still accessible):
         '_cs',
         '_raw',
         addr_size
         address
         avx_cc
         avx_rm
         avx_sae
         bytes: bytearray     underlying machine bytes for the instruction
         disp
         disp_offset
         disp_size
         eflags
         errno
         group                 verify if insn belongs to group using group id (x86.X86_GRP_*)
         group_name            for a given group_id, get its name as a string
         groups                list of groups the instr belongs to, if any
         id:                   instruction identifier, _raw.id, x86.X86_INS_*
         imm_offset
         imm_size
         insn_name             method to get the mnemonic name (just use mnemonic)
         mnemonic: str         i.e., 'cmp'
         modrm
         modrm_offset
         op_count: int         get # of operands that have the same op type
         op_find(op_type, pos) get op at position that have the specified type
         op_str: str           i.e., 'dword ptr [0x12a2c35e], 0x73477f76'
         opcode                list of opcodes as ints (prefer `bytes`)
         operands              list of operands
         prefix
         reg_name: str         get the register name given its id
         reg_read: bool        verify if insn implicitly read at specified register id
         reg_write: bool       verify if insn implicitly wrote at specified register id
         regs_access: list     list of all regs touched (r/w), incl. implicit ones
         regs_read: List[int]  list of all implicit registers being read
         regs_write: List[int] list of all implicit registers being modified
         rex
         sib
         sib_base
         sib_index
         sib_scale
         size: int             length of `CsInsn.bytes`, _raw.size
         sse_cc
         xop_cc
    """

    def __init__(self, csinsn):
        super().__init__(csinsn._cs, csinsn._raw)

    def __repr__(self):
        hex_bytes = f'({self.bytes.hex()})'
        return f'<x86Instr> {self.ea:#08x} {hex_bytes:<25} {self.mnemonic} {self.op_str}'


    # mimic certain properties in IDA to keep sane b/w the two
    @property
    def ea(self) -> int: return self.address

    @property
    def Op1(self) -> x86.X86Op: return self.operands[0]

    @property
    def Op2(self) -> x86.X86Op: return self.operands[1]

    @property
    def Op3(self) -> x86.X86Op: return self.operands[2]

    @property
    def itype(self) -> int: return self.id

    def has_prefix(self) -> bool:
        # @NOTE: capstone doesn't store this is prefix array: why?
        return self.rex or any(p != 0 for p in self.prefix)

    @property
    def is_rip_relative(self): return 'rip' in self.op_str

    #--------------------------------------------------------------------------
    # Operand Utilities
    #
    # Types of Operands:
    #    X86_OP_INVALID = 0
    #    X86_OP_REG     = 1
    #    X86_OP_IMM     = 2
    #    X86_OP_MEM     = 3
    @property
    def is_op1_reg(self) -> bool:   return self.Op1.type == x86.X86_OP_REG

    @property
    def is_op2_reg(self) -> bool:   return self.Op2.type == x86.X86_OP_REG

    @property
    def is_op3_reg(self) -> bool:   return self.Op3.type == x86.X86_OP_REG

    @property
    def is_op1_imm(self) -> bool:   return self.Op1.type == x86.X86_OP_IMM

    @property
    def is_op2_imm(self) -> bool:   return self.Op2.type == x86.X86_OP_IMM

    @property
    def is_op3_imm(self) -> bool:   return self.Op3.type == x86.X86_OP_IMM

    @property
    def is_op1_mem(self) -> bool:   return self.Op1.type == x86.X86_OP_MEM

    @property
    def is_op2_mem(self) -> bool:   return self.Op2.type == x86.X86_OP_MEM

    @property
    def is_op3_mem(self) -> bool:   return self.Op3.type == x86.X86_OP_MEM

    # @TODO: this might be overkill, as nothing wrong with getting it as `OpX.imm`
    def get_op1_imm(self) -> bool:  return self.Op1.imm
    def get_op2_imm(self) -> bool:  return self.Op2.imm
    def get_op3_imm(self) -> bool:  return self.Op3.imm


    def is_stack_mem_ref(self):
        """ i.e., [rsp]"""
        if (
            self.is_op1_mem and
            self.Op1.mem.disp == 0 and self.Op1.mem.base == x86.X86_REG_RSP
        ):
            return True
        elif (
            self.is_op2_mem and
            self.Op2.mem.disp == 0 and self.Op2.mem.base == x86.X86_REG_RSP
        ):
            return True
        return False

    def is_op1_reg_rsp(self):
        return self.is_op1_reg and self.Op1.reg == x86.X86_REG_RSP

    def is_op2_reg_rsp(self):
        return self.is_op2_reg and self.Op2.reg == x86.X86_REG_RSP

    # MEM operands
    #
    # Example Instruction:
    # <x86Instr 0x44e248 (8b0c8dccf64600)> mov ecx, dword ptr [ecx*4 + 0x46f6cc]
    #    instr.Op1.type == x86.X86_OP_REG
    #    instr.Op1.reg == x86.X86_REG_ECX
    #    -----------------------------------------
    #    instr.Op2.type == x86.X86_OP_MEM
    #    instr.Op2.mem.disp  -> 4650700 (0x46F6CC)
    #    instr.Op2.mem.scale -> 4
    #    instr.Op2.mem.index == x86.X86_REG_ECX
    #    instr.Op1.mem.base == 0

    # Common Instruction Types (@NOTE: not exhaustive, add to list)

    # Misc
    def is_cpuid(self):   return self.id == x86.X86_INS_CPUID
    def is_rdtsc(self):   return self.id == x86.X86_INS_RDTSC
    def is_nop(self):     return self.id == x86.X86_INS_NOP
    def is_int3(self):    return self.id == x86.X86_INS_INT3

    # Control Flow (can use `get_op1_imm` for the targets)
    def is_ret(self):     return self.id == x86.X86_INS_RET
    def is_call(self):    return self.id == x86.X86_INS_CALL
    def is_jmp(self):     return self.id == x86.X86_INS_JMP
    def is_jcc(self):
        return (
            self.id in [
                x86.X86_INS_JA,    x86.X86_INS_JAE,  x86.X86_INS_JB,
                x86.X86_INS_JBE,   x86.X86_INS_JCXZ, x86.X86_INS_JE,
                x86.X86_INS_JECXZ, x86.X86_INS_JG,   x86.X86_INS_JGE,
                x86.X86_INS_JL,    x86.X86_INS_JLE,  x86.X86_INS_JNE,
                x86.X86_INS_JNO,   x86.X86_INS_JNP,  x86.X86_INS_JNS,
                x86.X86_INS_JO,    x86.X86_INS_JP,   x86.X86_INS_JRCXZ,
                x86.X86_INS_JS
            ]
        )
    def get_jcc_target(self):
        return None if not self.is_jcc() else self.Op1.imm

    def get_call_target_imm(self):
        return self.ea + self.size + self.Op1.imm

    # @TODO: technically this will work for JMP r/m64
    def get_call_target_mem(self):
        return self.ea + self.size + self.Op1.mem.disp

    @property
    def disp_dest(self):
        """
        Since Capstone (when using `detail`) already identifes whether
        the decoded instruction has a displacement (and where), can
        simply use it instead of knowing upfront what operand has the
        displacement. Here we calculate the full destination that the
        displacement references. It assumes `ea` is valid and meaningful

        @NOTE: `use_detail` needs to be set
        """
        return (
            self.ea + self.size + self.disp if self.disp != 0
            else 0
        )

    def is_setcc(self):
        return (
            self.id in [
                x86.X86_INS_SETA, x86.X86_INS_SETAE, x86.X86_INS_SETB,
                x86.X86_INS_SETBE, x86.X86_INS_SETE, x86.X86_INS_SETG,
                x86.X86_INS_SETGE, x86.X86_INS_SETL, x86.X86_INS_SETLE,
                x86.X86_INS_SETNE, x86.X86_INS_SETNO, x86.X86_INS_SETNP,
                x86.X86_INS_SETNS, x86.X86_INS_SETO, x86.X86_INS_SETP,
                x86.X86_INS_SETS
            ]
        )

    def setcc_to_jcc(self):
        match self.id:
            case x86.X86_INS_SETA:    return x86.X86_INS_JA
            case x86.X86_INS_SETAE:   return x86.X86_INS_JAE
            case x86.X86_INS_SETB:    return x86.X86_INS_JB
            case x86.X86_INS_SETBE:   return x86.X86_INS_JBE
            case x86.X86_INS_SETE:    return x86.X86_INS_JE
            case x86.X86_INS_SETG:    return x86.X86_INS_JG
            case x86.X86_INS_SETGE:   return x86.X86_INS_JGE
            case x86.X86_INS_SETL:    return x86.X86_INS_JL
            case x86.X86_INS_SETLE:   return x86.X86_INS_JLE
            case x86.X86_INS_SETNE:   return x86.X86_INS_JNE
            case x86.X86_INS_SETNO:   return x86.X86_INS_JNO
            case x86.X86_INS_SETNP:   return x86.X86_INS_JNP
            case x86.X86_INS_SETNS:   return x86.X86_INS_JNS
            case x86.X86_INS_SETO:    return x86.X86_INS_JO
            case x86.X86_INS_SETP:    return x86.X86_INS_JP
            case x86.X86_INS_SETS:    return x86.X86_INS_JS

    # most explicit way to do this with CS, that i'm aware of
    def is_ncall_abs_indirect(self):
        return self.is_call() and self.bytes[:2] == b'\xFF\x15'

    def is_njmp_abs_indirect(self):
        return self.is_jmp() and self.bytes[:2] == b'\xFF\x25'


    # @NOTE: mark it explicit somewhere that this is explicit to a register,
    #        and register only i.e., [reg+<off>] are memory operands, which
    #        this doesn't account for
    def is_jmp_reg(self):    return self.is_jmp() and self.is_op1_reg
    def is_call_reg(self):   return self.is_call() and self.is_op1_reg


    # copy
    def is_lea(self):     return self.id == x86.X86_INS_LEA
    def is_xchg(self):    return self.id == x86.X86_INS_XCHG
    def is_mov(self):     return self.id == x86.X86_INS_MOV
    def is_movzx(self):   return self.id == x86.X86_INS_MOVZX
    def is_cmov(self):
        return (
            self.id in [
                x86.X86_INS_CMOVA, x86.X86_INS_CMOVAE, x86.X86_INS_CMOVB, x86.X86_INS_CMOVBE,
                x86.X86_INS_CMOVE, x86.X86_INS_CMOVG, x86.X86_INS_CMOVGE, x86.X86_INS_CMOVL,
                x86.X86_INS_CMOVLE, x86.X86_INS_CMOVNE, x86.X86_INS_CMOVNO, x86.X86_INS_CMOVNP,
                x86.X86_INS_CMOVNS, x86.X86_INS_CMOVO, x86.X86_INS_CMOVP, x86.X86_INS_CMOVS
            ]
        )
    def is_fcmov(self):
        return (
            self.id in [
                x86.X86_INS_FCMOVE,x86.X86_INS_FCMOVNBE, x86.X86_INS_FCMOVNB,
                x86.X86_INS_FCMOVNE, x86.X86_INS_FCMOVNU, x86.X86_INS_FCMOVU
            ]
        )

    # alu
    def is_not(self):     return self.id == x86.X86_INS_NOT
    def is_test(self):    return self.id == x86.X86_INS_TEST
    def is_and(self):     return self.id == x86.X86_INS_AND
    def is_cmp(self):     return self.id == x86.X86_INS_CMP
    def is_sub(self):     return self.id == x86.X86_INS_SUB
    def is_add(self):     return self.id == x86.X86_INS_ADD
    def is_shl(self):     return self.id == x86.X86_INS_SHL
    def is_shr(self):     return self.id == x86.X86_INS_SHR
    def is_shld(self):    return self.id == x86.X86_INS_SHLD
    def is_shrd(self):    return self.id == x86.X86_INS_SHRD
    def is_div(self):     return self.id == x86.X86_INS_IDIV
    def is_idiv(self):    return self.id == x86.X86_INS_DIV
    def is_mul(self):     return self.id == x86.X86_INS_MUL
    def is_imul(self):    return self.id == x86.X86_INS_IMUL

    # stack
    def is_push(self):    return self.id == x86.X86_INS_PUSH
    def is_pushfd(self):  return self.id == x86.X86_INS_PUSHFD
    def is_pushfq(self):  return self.id == x86.X86_INS_PUSHFQ
    def is_pop(self ):    return self.id == x86.X86_INS_POP
    def is_popfd(self):   return self.id == x86.X86_INS_POPFD
    def is_popfq(self):   return self.id == x86.X86_INS_POPFQ
    # ---------------------------------------------------------

# -----------------------------------------------------------------------------
class x86Disasm:
    """Thin wrapper around quickly instantiating an x86 disassembly engine"""

    def __init__(self, is64=False, imgbuffer: bytes = None):
        self._md = create_disasm_engine(is64)  # diassembly engine
        self._data = imgbuffer                 # underlying pre-fixed imgbuffer to decode against via offset

    def decode(self, code: bytes, offset:int =0):
        """Decode single instruction from a given given buffer with an optional offset/addr

        @example
           md = X86Disasm()
           md.decode(bytes.fromhex("66 F7 05 A3 EA A4 12 D3 E0"))
               <CsInsn 0x0 [66f705a3eaa412d3e0]: test word ptr [0x12a4eaa3], 0xe0d3>
           md.decode(bytes.fromhex("83 3D 76 16 A6 12 01"))
               <CsInsn 0x0 [833d7616a61201]: cmp dword ptr [0x12a61676], 1>
        """
        return x86Instr(next(self._md.disasm(code, offset)))

    def decode_range(self, code: bytes, offset=0):
        """Decode series of instructions given the provided code buffer"""
        r = self._md.disasm(code, offset)
        for insn in r: yield x86Instr(insn)

    def decode_img(self, offset:int):
        """Decode at offset in the underlying data buffer specified on init"""
        end_offset = min(len(self._data), offset+15)
        ops: bytes = self._data[offset:end_offset]
        return x86Instr(next(self._md.disasm(ops, offset)))

    def decode_range_img(self, offset: int):
        r = self._md.disasm(self._data[offset:], offset)
        for insn in r: yield x86Instr(insn)

    @staticmethod
    def examples():
        return """
            md = x86Disasm()
            md.decode(bytes.fromhex("66 F7 05 A3 EA A4 12 D3 E0"))
              <CsInsn 0x0 [66f705a3eaa412d3e0]: test word ptr [0x12a4eaa3], 0xe0d3>

            md.decode(bytes.fromhex("83 3D 76 16 A6 12 01"))
              <CsInsn 0x0 [833d7616a61201]: cmp dword ptr [0x12a61676], 1>
        """

# @TODO: there is still code that references and utilizes this, eventually
#        remove it completely and replace with with the above
class x86Decoder:
    def __init__(self, imgbuffer: bytes, is64: bool=True):
        """Initialize a disassembler for a given x86 architecture with the
           underlying image buffer that contains all of the relevant data.
           It is a disassembler specific to this image buffer
        """
        self.md = create_disasm_engine(is64)
        self.data = imgbuffer

    def decode(self, offset: int) -> x86Instr:
        """given an offset into an image buffer, decode the instr at the offset"""
        # @TODO: best way to read the opcodes in from variety of image buffers
        ops: bytes = self.data[offset:offset+15]
        return x86Instr(next(self.md.disasm(ops, offset)))

    def decode_buffer(self, ops: bytes, offset: int = 0) -> x86Instr:
        """given a buffer of bytes, decode the instr from it"""
        # @TODO: best way to read the opcodes in from variety of image buffers
        return x86Instr(next(self.md.disasm(ops, offset)))

    def decode_next(self, offset: int) -> x86Instr:
        """given an offset into an image buffer, decode the next insstr from the offset"""
        instr = self.decode(offset)
        return self.decode(instr.address+instr.size)

    def decode_next_incl_jmp(self, offset: int) -> x86Instr:
        """decode from offset, the next instr, which if it's a `jmp loc`, implies it's target

            This is a common compiler obfuscation primitive, where the interest
            is to ignore the uncoditional jmps that scatter the control flow
        """
        next_instr = self.decode_next(offset)
        if next_instr.is_jmp():
            return self.decode(next_instr.get_op1_imm())
        return next_instr

    def decode_next_insn(self, instr: x86Instr) -> x86Instr:
        """given an `x86Instr` object, decode the next insn after it"""
        ea = instr.ea + instr.size
        return self.decode(ea)

    def decode_next_insn_incl_jmp(self, instr: x86Instr) -> x86Instr:
        """decode the next instr, which if it's a `jmp loc`, implies it's target

            This is a common compiler obfuscation primitive, where the interest
            is to ignore the uncoditional jmps that scatter the control flow
        """
        next_instr = self.decode_next_insn(instr)
        if next_instr.is_jmp():
            return self.decode(next_instr.get_op1_imm())
        return next_instr