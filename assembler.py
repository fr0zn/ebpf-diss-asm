#!/usr/bin/env python
import sys
import struct

SIZE = 64

def _pack(opcode, dst=0, src=0, offset=0, immediate=0):
    # msb                                                        lsb
    # +------------------------+----------------+----+----+--------+
    # |immediate               |offset          |src |dst |opcode  |
    # +------------------------+----------------+----+----+--------+
    dst_src = dst | (src << 4)
    #print hex(dst),hex(src), hex(offset), hex(immediate)
    return struct.pack('<BBhl', opcode, dst_src, offset, immediate)

def _parse_off(off):
    return int(off)

def _parse_reg(line):
    return int(line.split('r')[1])

def _parse_imm(line):
    return int(line.split('#')[1])

def _parse_reg_offset(line):
    line = line.replace('[','').replace(']','')
    if '-' in line:
        _reg, _off = line.split('-')
        _off = '-'+_off
    elif '+' in line:
        _reg, _off = line.split('+')
    else:
        _reg, _off = line, 0
    _reg = _parse_reg(_reg)
    _off = _parse_off(_off)
    return _reg, _off

def none(opcode, regs):
    return _pack(opcode, 0, 0 , 0, 0)

def imm(opcode, regs):
    _imm = _parse_imm(regs.strip())
    return _pack(opcode, 0, 0 , 0, _imm)

def off_branch(opcode, regs):
    _off = _parse_off(regs.strip())
    return _pack(opcode, 0, 0 , 0, 0)

def dst_imm(opcode, regs):
    _dst, _imm = regs.split(',')
    _dst = _parse_reg(_dst.strip())
    _imm = _parse_imm(_imm.strip())
    return _pack(opcode, _dst, 0 , 0, _imm)

def dst_src(opcode, regs):
    _dst, _src = regs.split(',')
    _dst = _parse_reg(_dst.strip())
    _src = _parse_reg(_src.strip())
    return _pack(opcode, _dst, _src , 0, 0)

def src_dst_imm(opcode, regs):
    _src, _dst, _imm = regs.split(',')
    _dst = _parse_reg(_dst.strip())
    _src = _parse_reg(_src.strip())
    _imm = _parse_imm(_imm.strip())
    return _pack(opcode, _dst, _src , 0, _imm)

def dst_src_off(opcode, regs):
    _dst, _src_off = regs.split(',')
    _dst = _dst.strip()
    _src_reg, _off = _parse_reg_offset(_src_off.strip())
    _dst_reg = _parse_reg(_dst)
    return _pack(opcode, _dst_reg, _src_reg, _off, 0)


def dst_off_imm(opcode, regs):
    _dst_off, _imm = regs.split(',')
    _dst_off = _dst_off.strip()
    _imm = _parse_imm(_imm.strip())
    _reg, _off = _parse_reg_offset(_dst_off)
    return _pack(opcode, _reg, 0, _off, _imm)

def dst_off_src(opcode, regs):
    _dst_off, _src = regs.split(',')
    _dst, _off = _parse_reg_offset(_dst_off.strip())
    _src = _parse_reg(_src.strip())
    return _pack(opcode, _dst, _src, _off, 0)

def dst_imm_off(opcode, regs):
    _dst, _imm, _off = regs.split(',')
    _dst = _parse_reg(_dst.strip())
    _imm = _parse_imm(_imm.strip())
    _off = _parse_off(_off.strip())
    return _pack(opcode, _dst, 0, _off, _imm)

def dst_src_off_branch(opcode, regs):
    _dst, _src, _off = regs.split(',')
    _dst = _parse_reg(_dst.strip())
    _src = _parse_reg(_src.strip())
    _off = _parse_off(_off.strip())
    return _pack(opcode, _dst, _src, _off, 0)


CODES = {   
'_alu': {
    #                 imm,             reg
    # 64 ALU 
    'add':  [(0x07, dst_imm), (0x0f, dst_src)],
    'sub':  [(0x17, dst_imm), (0x1f, dst_src)],
    'mul':  [(0x27, dst_imm), (0x2f, dst_src)],
    'div':  [(0x37, dst_imm), (0x3f, dst_src)],
    'or':   [(0x47, dst_imm), (0x4f, dst_src)],
    'and':  [(0x57, dst_imm), (0x5f, dst_src)],
    'lsh':  [(0x67, dst_imm), (0x6f, dst_src)],
    'rsh':  [(0x77, dst_imm), (0x7f, dst_src)],
    'neg':  [(0x87, dst_imm), (None, dst_src)],
    'mod':  [(0x97, dst_imm), (0x9f, dst_src)],
    'xor':  [(0xa7, dst_imm), (0xaf, dst_src)],
    'mov':  [(0xb7, dst_imm), (0xbf, dst_src)],
    'arsh': [(0xc7, dst_imm), (0xcf, dst_src)],
    # 32 ALU
    'add32':  [(0x04, dst_imm), (0x0c, dst_src)],
    'sub32':  [(0x14, dst_imm), (0x1c, dst_src)],
    'mul32':  [(0x24, dst_imm), (0x2c, dst_src)],
    'div32':  [(0x34, dst_imm), (0x3c, dst_src)],
    'or32':   [(0x44, dst_imm), (0x4c, dst_src)],
    'and32':  [(0x54, dst_imm), (0x5c, dst_src)],
    'lsh32':  [(0x64, dst_imm), (0x6c, dst_src)],
    'rsh32':  [(0x74, dst_imm), (0x7c, dst_src)],
    'neg32':  [(0x84, dst_imm), (None, dst_src)],
    'mod32':  [(0x94, dst_imm), (0x9c, dst_src)],
    'xor32':  [(0xa4, dst_imm), (0xac, dst_src)],
    'mov32':  [(0xb4, dst_imm), (0xbc, dst_src)],
    'arsh32': [(0xc4, dst_imm), (0xcc, dst_src)]
},
# Memory
'ldw':     (0x00, src_dst_imm),  # Documented? (dst_imm)
'ldh':     (0x08, src_dst_imm),  # Documented? (dst_imm)
'ldb':     (0x10, src_dst_imm),  # Documented? (dst_imm)
'lddw':    (0x18, src_dst_imm),  # or dst_imm
'ldabsw':  (0x20, src_dst_imm),
'ldabsh':  (0x28, src_dst_imm),
'ldabsb':  (0x30, src_dst_imm),
'ldabsdw': (0x38, src_dst_imm),
'ldindw':  (0x40, src_dst_imm),
'ldindh':  (0x48, src_dst_imm),
'ldindb':  (0x50, src_dst_imm),
'ldinddw': (0x58, src_dst_imm),

'ldxw':    (0x61, dst_src_off),
'ldxh':    (0x69, dst_src_off),
'ldxb':    (0x71, dst_src_off),
'ldxdw':   (0x79, dst_src_off),
'stw':     (0x62, dst_off_imm),
'sth':     (0x6a, dst_off_imm),
'stb':     (0x72, dst_off_imm),
'stdw':    (0x7a, dst_off_imm),
'stxw':    (0x63, dst_off_src),
'stxh':    (0x6b, dst_off_src),
'stxb':    (0x73, dst_off_src),
'stxdw':   (0x7b, dst_off_src),

# Branch
'ja':   (0x05, off_branch),
'call': (0x85, imm),
'exit': (0x95, none),
'_jmp': {
    'jeq':  [(0x05, dst_imm_off), (0x0d, dst_src_off_branch)],
    'jgt':  [(0x15, dst_imm_off), (0x1d, dst_src_off_branch)],
    'jge':  [(0x25, dst_imm_off), (0x2d, dst_src_off_branch)],
    'jlt':  [(0xa5, dst_imm_off), (0xad, dst_src_off_branch)],
    'jle':  [(0xb5, dst_imm_off), (0xbd, dst_src_off_branch)],
    'jset': [(0x45, dst_imm_off), (0x4d, dst_src_off_branch)],
    'jne':  [(0x55, dst_imm_off), (0x5d, dst_src_off_branch)],
    'jsgt': [(0x65, dst_imm_off), (0x6d, dst_src_off_branch)],
    'jsge': [(0x75, dst_imm_off), (0x7d, dst_src_off_branch)],
    'jslt': [(0xc5, dst_imm_off), (0xcd, dst_src_off_branch)],
    'jsle': [(0xd5, dst_imm_off), (0xdd, dst_src_off_branch)],
},

}

def assembler_instruction(instruction):
    try:
        op, _ ,regs = instruction.lower().partition(' ')
        regs = regs.replace(" ", "").strip()

        # Alu has 2 types for each opcode, reg and imm
        if op in CODES['_alu']:
            code = CODES['_alu'][op]
            if '#' in regs:
                code, func = code[0] # imm
            else:
                code, func = code[1] # reg
            return func(code, regs)
        elif op in CODES:
            code, func = CODES[op]
            return func(code, regs)
        elif op in CODES['_jmp']:
            code = CODES['_jmp'][op]
            if '#' in regs:
                code, func = code[0] # imm
            else:
                code, func = code[1] # reg
            return func(code, regs)
    except:
        pass
    print "(Invalid, instruction)", instruction
    sys.exit(1)

def assembler(program):
    out = ""
    for line in program.strip().split('\n'):
        line = line.strip()
        out += assembler_instruction(line)
    return out


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print "Usage: {} program.asm ".format(sys.argv[0])
        sys.exit(1)

    p = open(sys.argv[1],'r').read().strip()

    print assembler(p)

