#! /usr/bin/env python
import angr
import sys
from barf.barf import BARF 
import pyvex
import claripy
import copy
from pydot import Dot
from pydot import Edge
from pydot import Node
from pygments.formatters import HtmlFormatter
from pygments.lexers.asm import NasmLexer
from pygments import highlight

def bb_get_instr_max_width(basic_block):
    """Get maximum instruction mnemonic width
    """
    asm_mnemonic_max_width = 0

    for dinstr in basic_block:
        if len(dinstr.asm_instr.mnemonic) > asm_mnemonic_max_width:
            asm_mnemonic_max_width = len(dinstr.asm_instr.mnemonic)

    return asm_mnemonic_max_width

def statement_inspect(state):
    global modified_value
    expressions = state.scratch.irsb.statements[state.inspect.statement].expressions
    if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
        state.scratch.temps[expressions[0].cond.tmp] = modified_value
        state.inspect._breakpoints['statement'] = []

def symbolic_compute(angr_proj, block_addr, modifed = None, inspected = False):
    '''
        Use symbolic execution to compute the successor of the basicblock which
        start with block_addr

        Args:
            angr_pro: angr project
            block_addr: basic block's start address
            modifed: the modified value
            inspected: should inspect the every statement whether
        Returns:
            the successor basic block's address
    '''
    # if hook_list != None:
    #     for hooked in hook_list:
    #         angr_proj.hook(hooked, length = 5)
    global modified_value, normal_exit_blocks
    if modifed != None:
        modified_value = modifed
    state = angr_proj.factory.blank_state(addr = block_addr, add_options={angr.options.CALLLESS},remove_options={angr.options.LAZY_SOLVES})
    
    if inspected:
        state.inspect.b('statement', when = angr.BP_BEFORE, action = statement_inspect)
    #p = angr_proj.factory.path(state)
    #print(p.successors)
    new_states = angr_proj.factory.successors(state).flat_successors
    s = new_states[0]
    while s.addr not in normal_exit_blocks:
        new_states = angr_proj.factory.successors(s).flat_successors
        s = new_states[0]
    return s.addr

def render_asm(instr, address):
    formatter = HtmlFormatter()
    formatter.noclasses = True
    formatter.nowrap = True

    #asm_str = instr.prefix + " " if instr.prefix else ""
    asm_str = instr

    asm_str = highlight(asm_str, NasmLexer(), formatter)
    asm_str = asm_str.replace("span", "font")
    asm_str = asm_str.replace('style="color: ', 'color="')
    asm_str = asm_str.replace('style="border: 1px solid ', 'color="')

    asm_tpl = "<tr><td align='left'>{address:08x} {assembly} </td></tr>"
    return asm_tpl.format(address=address, assembly=asm_str)

def unflat(angr_proj, barf_proj, function):
    '''
    Given the angr proejct and its function address, unflat the cfg

    Args:
        angr_proj : angr project
        barf_proj : barf project
        fucntion: the analysed function
    
    Returns:

    '''

    #prelogue_block = None
    address = function.addr
    f_cfg = barf_proj.recover_cfg(start = address)
    blocks_list = f_cfg.basic_blocks
    prelogue_block = f_cfg.find_basic_block(address)
    try:
        main_dispatcher = prelogue_block.direct_branch
    except:
        return
    

    exit_blocks = list()
    normal_blocks = list()
    nop_blocks = list()
    predispatcher_address = 0

    ### First, need find the predispatcher
    for temp_block in blocks_list:
        if temp_block.direct_branch == main_dispatcher:
            predispatcher_address = temp_block.start_address
        elif len(temp_block.branches) == 0 and temp_block.direct_branch == None:
            exit_blocks.append(temp_block.start_address)
    ### End find the predispatcher
    
    ### Specify the normal blocks and nop blocks
    for temp_block in blocks_list:
        if temp_block.direct_branch == predispatcher_address and len(temp_block.instrs) != 1:
            normal_blocks.append(temp_block.start_address)
        elif temp_block.start_address != address and temp_block.start_address not in exit_blocks:
            nop_blocks.append(temp_block)
    ### End specify the blocks
    
    if len(normal_blocks) == 0:
        print("The function %s don't be obfuscated" % function.name)
        return

    ## Symbolic execution to find the blocks' sequence
    print(len(normal_blocks))
    normal_blocks.append(address)
    global normal_exit_blocks
    normal_exit_blocks = copy.deepcopy(normal_blocks)
    normal_exit_blocks.extend(exit_blocks)
    relationships = dict()
    patch_instrs = dict()
    
    for temp_block in normal_exit_blocks:
        relationships[temp_block] = list()
    
    for temp_start in normal_blocks:
        temp_block = f_cfg.find_basic_block(temp_start)
        branches = False
        #hook = list()
        for inst in temp_block.instrs:
            if inst.asm_instr.mnemonic.startswith('cmov'):
                patch_instrs[temp_start] = inst.asm_instr
                branches = True
            #elif inst.asm_instr.mnemonic.startswith('call'):
            #    hook.append(inst.addr)

        if branches: ##if it has branches, we should traverse the every branch
            relationships[temp_start].append(symbolic_compute(angr_proj, temp_start, claripy.BVV(1, 1), True))
            relationships[temp_start].append(symbolic_compute(angr_proj, temp_start, claripy.BVV(0, 1), True))
        else:
            relationships[temp_start].append(symbolic_compute(angr_proj, temp_start))
        
    ###End get the basic block relationships
    f_cfg.save(function.name+"_origin", format = "png")
    
    ###output the dot graph
    dot_graph = Dot(function.name+".dot")

    node_color = {
        'entry': 'orange',
        'exit': 'gray',
        'other': 'black',
    }

    node_format = {
        'fontname': 'monospace',
        'fontsize': 9.0,
        'penwidth': 0.5,
        'rankdir': 'LR',
        'shape': 'plaintext',
    }

    nodes = {}
    bb_tpl = '<'
    bb_tpl += '<table border="1.0" cellborder="0" cellspacing="1" cellpadding="0" valign="middle">'
    bb_tpl += '  <tr><td align="center" cellpadding="1" port="enter"></td></tr>'
    bb_tpl += '  <tr><td align="left" cellspacing="1">{label}</td></tr>'
    bb_tpl += '  {assembly}'
    bb_tpl += '  <tr><td align="center" cellpadding="1" port="exit" ></td></tr>'
    bb_tpl += '</table>'
    bb_tpl += '>'
        

    for node_address, node_list in relationships.items():
        temp_block = f_cfg.find_basic_block(node_address)
        asm_mnemonic_max_width = bb_get_instr_max_width(temp_block) + 1
        lines = list()
        if len(node_list) == 1:
            for dinstr in temp_block:
                dinstr = dinstr.asm_instr
                if dinstr.mnemonic.startswith('jmp'):
                    origin_str = 'jmp ' + (' ' * (asm_mnemonic_max_width - len(dinstr.mnemonic))) + hex(node_list[0])
                else:
                    oprnds_str = ", ".join([oprnd.to_string() for oprnd in dinstr.operands])
                    origin_str = dinstr.mnemonic + (' ' * (asm_mnemonic_max_width - len(dinstr.mnemonic)))
                    origin_str += " " + oprnds_str if oprnds_str else ""

                lines.append(render_asm(origin_str, dinstr.address))
        elif len(node_list) == 2:
            for dinstr in temp_block:
                dinstr = dinstr.asm_instr
                if dinstr.mnemonic.startswith('cmov'):
                    origin_str = 'j' + dinstr.mnemonic[4:]
                    origin_str += (' ' * (asm_mnemonic_max_width - len(origin_str)))
                    origin_str += ' ' + hex(node_list[0])
                    lines.append(render_asm(origin_str, dinstr.address))
                    origin_str = 'jmp'
                    origin_str += (' ' * (asm_mnemonic_max_width - len(origin_str)))
                    origin_str += hex(node_list[1])
                    lines.append(render_asm(origin_str, dinstr.address))
                    break
                else:
                    oprnds_str = ", ".join([oprnd.to_string() for oprnd in dinstr.operands])
                    origin_str = dinstr.mnemonic + (' ' * (asm_mnemonic_max_width - len(dinstr.mnemonic)))
                    origin_str += " " + oprnds_str if oprnds_str else ""
                    lines.append(render_asm(origin_str, dinstr.address))
        else:
            for dinstr in temp_block:
                dinstr = dinstr.asm_instr
                oprnds_str = ", ".join([oprnd.to_string() for oprnd in dinstr.operands])
                origin_str = dinstr.mnemonic + (' ' * (asm_mnemonic_max_width - len(dinstr.mnemonic)))
                origin_str += " " + oprnds_str if oprnds_str else ""
                lines.append(render_asm(origin_str, dinstr.address))
        
        bb_dump = "".join(lines)

        bb_addr = temp_block.address
        if temp_block.is_entry:
            bb_label = "{} @ {:x}".format(function.name, bb_addr)
        else:
            bb_label = "loc_{:x}".format(bb_addr)
        
        bb_formated = bb_tpl.format(label=bb_label, assembly=bb_dump)

        if temp_block.is_entry:
            bb_type = "entry"
        elif node_address in exit_blocks:
            bb_type = "exit"
        else:
            bb_type = "other"

        created_node = Node(temp_block.address, label = bb_formated, color = node_color[bb_type], **node_format)
        nodes[node_address] = created_node
        dot_graph.add_node(created_node)
        ###End write node

    ###Write Edge
    for node_address, node_list in relationships.items():
        if len(node_list) == 1:
            created_edge = Edge(nodes[node_address], nodes[node_list[0]], color = 'blue')
            dot_graph.add_edge(created_edge)
        elif len(node_list) == 2:
            created_edge = Edge(nodes[node_address], nodes[node_list[0]], color = 'darkgreen')
            dot_graph.add_edge(created_edge)
            created_edge = Edge(nodes[node_address], nodes[node_list[1]], color = 'red')
            dot_graph.add_edge(created_edge)
    ###End write edge

    dot_graph.write_png(function.name+"_unflat.png")




        
if __name__ == '__main__':
    if(len(sys.argv) < 2):
        print("Please input the unplat binary")
        exit(-1)

    angr_proj = angr.Project(sys.argv[1], load_options={'auto_load_libs' : False})
    barf_proj = BARF(sys.argv[1])
    angr_cfg = angr_proj.analyses.CFGFast()
    unanalysis_function = ['init_proc', '__libc_start_main', '__gmon_start', '_start', 'deregister_tm_clones',
    'register_tm_clones', 'register_tm_clones', '__do_global_dtors_aux', 'frame_dummy', '__libc_csu_init',
    'libc_csu_fini', '_term_proc', '__libc_start_main']
    function_manager = angr_proj.kb.functions
    print(dict(function_manager))
    for k in dict(function_manager):
        name = function_manager[k].name
        if name not in unanalysis_function and name.startswith('__libc_start_main') == False:
            print(name)
            unflat(angr_proj, barf_proj, function_manager[k])