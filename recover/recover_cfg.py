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

"""Core logic for CFG recovery

Exposes the internal "stepping" routines responsible for the raw CFG recovery and
normalization pass and also where the actual mutation rules are utilized.
    - recover_cfg_step
    - normalize_raw_recovery

"""

#-------------------------------------------------------------------------------
import collections
from typing import List, Dict, Set, Optional

from recover.recover_core import (
    ProtectedInput64,
    RecoveredInstr,
    RuleResult,
    x86Instr,
    dataclass, field
)

"""--------------------------------CFG Result--------------------------------"""
"""
  :func_ea:  function start address the CFG represents
  :recovered_instrs:  all recovered instructions (raw recovery)
  :normalized_flow:   normalized recovery (work with this)
  :ea_to_recovered:   lookup table - instr ea -> recovered instr
  :obf_backbone:      complete backbone links specific to this CFG
"""
CFGResult = collections.namedtuple(  # cannot unpack data class
    "CFGResult", [
        "func_ea",          # int
        "recovered_instrs", # list[RecoveredInstr]
        "normalized_flow",  # list[RecoveredInstr]
        "ea_to_recovered",  # dict[int,RecoveredInstr]
        "obf_backbone"      # dict[int,int]
    ]
)

@dataclass
class CFGStepState:
    """Represents the recovery state for a controlled-step-CFG traversal.

    :func_start_ea:   the start address of the function to recover
    :rules:           list of rules that dictate how step works

    :recovered:       all recovered, original instructions inside the function boundary
    :ea_to_recovered: easy access map from an ea to its recovered function
    :obf_backbone:    map between an obfuscator's instr ea to its destination target

    :normalized_flow: reconstructed linear "normalized" execution flow of the recovery
    :ea_to_linear:    lookup utilized in linear flow recovery for quick refs to parsed instrs

    :to_explore:      DFS stack
    :visited:         visited locations
    """
    func_start_ea: int

    log: bool = False

    recovered:       List[RecoveredInstr]     = field(default_factory=list)
    ea_to_recovered: Dict[int,RecoveredInstr] = field(default_factory=dict)
    obf_backbone:    Dict[int,int]            = field(default_factory=dict)

    normalized_flow: List[RecoveredInstr]     = field(default_factory=list)
    ea_to_linear:    Dict[int,RecoveredInstr] = field(default_factory=dict)

    to_explore:      List[int]                = field(init=False)
    visited:         Set[int]                 = field(default_factory=set)

    MAX_INSTRS: int                = 30000  # Safety net to prevent infinite loops
    prev_instr: Optional[x86Instr] = None   # Debug helper

    def __post_init__(self):
        self.to_explore = [self.func_start_ea]


"""-------------------------Recover CFG via Stepping-------------------------"""
def recover_cfg_step(
    d: ProtectedInput64,
    func_start_ea: int,
    LOG: bool=False
) -> CFGResult:
    """
    Given a start address of a presumed function, recover its control flow using
    the set of mutation rules specified in ProtectedInput64

    LOG: logs the individual stepping, useful for debugging
    """
    #---------------------------------------------------------------------------
    from enum import Enum
    class StepResult(Enum):
        CONTINUE = 0
        STOP = 1

    def _step(
        d: ProtectedInput64,
        s: CFGStepState
    ) -> StepResult:
        if not s.to_explore:
            return False
        curr_ea: int = s.to_explore.pop()
        if (
            curr_ea in s.visited or
            len(s.recovered) >= s.MAX_INSTRS
        ):
            return True # Continue
        s.visited.add(curr_ea)
        #-----------------------------------------------------------------------
        try: # exceptions can throw on decoding
            s.prev_instr = instr = d.mdp.decode(curr_ea)
            if s.log:
                d.log.info(f'\t[RecoverCfg] {s.prev_instr}')
        except Exception as e:
            es = f'decoding failed at {curr_ea:08x} (prev_instr) {s.prev_instr}'
            d.log.error(es)
            raise ValueError(es)
        #-----------------------------------------------------------------------
        for rule in d.mutation_rules:
            match rule(d, s, instr):
                case RuleResult.NEXT_RULE: continue
                case RuleResult.CONTINUE:  return StepResult.CONTINUE
                case RuleResult.BREAK:
                    input("Add break logic here")
                    return StepResult.STOP
        s.recovered.append(
            RecoveredInstr(func_start_ea=s.func_start_ea,
                           instr=instr)
        )
        s.ea_to_recovered[instr.ea] = s.recovered[-1]
        s.to_explore.append(instr.ea + instr.size)
        return StepResult.CONTINUE
    #---------------------------------------------------------------------------
    # build the stepping state and do the raw recovery first
    s: CFGStepState = CFGStepState(func_start_ea=func_start_ea,log=LOG)
    while s.to_explore:
        if not _step(d,s):
            break

    normalize_raw_recovery(d, s)

    return CFGResult(
        func_ea=s.func_start_ea,
        recovered_instrs=s.recovered,
        normalized_flow=s.normalized_flow,
        ea_to_recovered=s.ea_to_recovered,
        obf_backbone=s.obf_backbone
    )


"""---------------------------Recover CFG via Emu----------------------------"""
def recover_cfg_emu(
    d: ProtectedInput64,
    func_start_ea: int
) -> CFGResult:
    """Generic recovery that ignores that specific obfuscator mutation patterns
    and emulates the CFG instead. This is naturally much more costly but avoids
    having to worry about knowing the mutation patterns. But therefore, it
    doesn't remove the mutations.
    """
    """
        emu = EmulateIntel64()
        emu.map_image(bytes(self.d.imgbuffer))
        emu.map_teb()
        snapshot = emu.context_save()
        ... ...
        emu.context_restore(snapshot)
        emu.pc = call_dispatch_ea
        ... ...
        emu.stepi()
        instr = next(emu.dis.disasm(emu.mem[emu.pc:emu.pc+15], emu.pc))
    """
    return NotImplemented

"""-------------------------Normalize Recovered Flow-------------------------"""
def normalize_raw_recovery(
    d: ProtectedInput64,
    s: CFGStepState
):
    assert s.recovered is not None or len(s.recovered) != 0
    #---------------------------------------------------------------------------
    # 3 helpers for the normalization
    def walk_backbone(instr_ea: int):
        """
            since the two utility checks don't track the dispatchers
            need to explicitly account for it here, otherwise the
            logic of this loop is useless
            TODO: can simply add the d.dispatcher_locs to obf_backbone
                  prior to the traversal
        """
        curr_ea = instr_ea
        while curr_ea in s.obf_backbone or curr_ea in d.dispatcher_locs:
            curr_ea = (
                d.dispatchers_to_target[curr_ea] if curr_ea in d.dispatcher_locs
                else s.obf_backbone[curr_ea]
            )
        return curr_ea
    #---------------------------------------------------------------------------
    def update_branch_targets():
        r: RecoveredInstr
        for r in s.normalized_flow:
            if r.instr.is_jcc() or (r.instr.is_jmp() and r.instr.is_op1_imm):
                # targets can still point to backbone
                branch_dest = walk_backbone(r.instr.Op1.imm)
                branch_str  = f'{r.instr.mnemonic} {branch_dest:#08x}'
                nb = d.ks.asm(branch_str, addr=r.instr.ea, as_bytes=True)[0]
                r.instr = d.mdp.decode_buffer(nb, r.instr.ea)
    #---------------------------------------------------------------------------
    def is_boundary_instr(r: RecoveredInstr):
        return (
            r.instr.is_ret() or r.instr.is_jmp() or r.instr.is_int3()
        )
    #---------------------------------------------------------------------------
    # normalize pass
    for i, r in enumerate(s.recovered):
        s.normalized_flow.append(r)
        s.ea_to_linear[r.instr.ea] = r
        #-----------------------------------------------------------------------
        if is_boundary_instr(r): continue
        #-----------------------------------------------------------------------
        fall_through_ea = walk_backbone(r.instr.ea + r.instr.size)
        if not fall_through_ea in s.ea_to_recovered:
            raise ValueError(f'Unexpected fall through address {fall_through_ea:08x} in {r}')
        #-----------------------------------------------------------------------
        if (
            i < len(s.recovered)-1 and
            s.recovered[i+1].instr.ea != fall_through_ea
        ):
            if fall_through_ea in s.ea_to_linear:
                sjr = f'jmp {fall_through_ea:#08x}'
                b = d.ks.asm(sjr, addr=r.instr.ea, as_bytes=True)[0]
                synthetic_jmp = d.mdp.decode_buffer(b, r.instr.ea)
                s.normalized_flow.append(
                    RecoveredInstr(func_start_ea=r.func_start_ea,
                                   instr=synthetic_jmp,
                                   linear_ea=-1, #curr_linear_ea,
                                   is_boundary_jmp=True)
                )
            else:
                connected_instr = s.ea_to_recovered[fall_through_ea]
                s.normalized_flow.append(connected_instr)
                s.ea_to_linear[connected_instr.instr.ea] = connected_instr
        elif (len(s.recovered) - 1) == i:
            # last instruction is not a known function boundary if this path is
            # reached. Add a synthetic boundary jmp to merge the boundary.
            # @NOTE: did I assert here becasue some JCC edge case I hit w/o recalling?
            assert fall_through_ea in s.ea_to_linear 
            #----------------------------------------------------------------------
            bjs = f'jmp {fall_through_ea:#08x}'
            b = d.ks.asm(bjs, addr=r.instr.ea, as_bytes=True)[0]
            boundary_jmp = d.mdp.decode_buffer(b, r.instr.ea)
            s.normalized_flow.append(
                RecoveredInstr(func_start_ea=s.func_start_ea,
                               instr=boundary_jmp,
                               is_boundary_jmp=True)
            )
    #---------------------------------------------------------------------------
    # updating before or alongside breaks how the fall through address is calculated
    update_branch_targets()