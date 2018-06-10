#!/usr/bin/env python
import sys
import struct

SIZE = 64

BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07 # BPF_ALU64 in eBPF
BPF_ALU64 = 0x07

# ld/ldx fields
SIZES = {
0x00: 'w',
0x08: 'h',
0x10: 'b',
0x18: 'dw',   # /* eBPF only, double word */
}

LDS = {
0x00: 'imm',
0x20: 'abs',
0x40: 'ind',
0x60: 'mem',
0x80: 'len',  # reserved in eBPF
0xa0: 'msh',  # reserved in eBPF
0xc0: 'xadd',  #/* eBPF only, exclusive add */
}

# alu fields
ALU = {
0x00: 'add' ,
0x10: 'sub' ,
0x20: 'mul' ,
0x30: 'div' ,
0x40: 'or' ,
0x50: 'and' ,
0x60: 'lsh' ,
0x70: 'rsh' ,
0x80: 'neg' ,
0x90: 'mod' ,
0xa0: 'xor' ,
0xb0: 'mov' ,   #/* eBPF only: mov reg to reg */
0xc0: 'arsh' ,   #/* eBPF only: sign extending shift right */
0xd0: 'end' ,   #/* eBPF only: endianness conversion */
}

# jmp fields
JMP = {
0x00: 'ja' ,
0x10: 'jeq' ,
0x20: 'jgt' ,
0x30: 'jge' ,
0x40: 'jset' ,
0x50: 'jne' ,  #/* eBPF only: jump != */
0x60: 'jsgt' ,  #/* eBPF only: signed '>' */
0x70: 'jsge' ,  #/* eBPF only: signed '>=' */
0x80: 'call' ,  #/* eBPF only: function call */
0x90: 'exit' ,  #/* eBPF only: function return */
0xa0: 'jlt' ,  #/* eBPF only: unsigned '<' */
0xb0: 'jle' ,  #/* eBPF only: unsigned '<=' */
0xc0: 'jslt' ,  #/* eBPF only: signed '<' */
0xd0: 'jsle' ,  #/* eBPF only: signed '<=' */
}

def int32(x):
  if x>0xFFFFFFFF:
    raise OverflowError
  if x>0x7FFFFFFF:
    x=int(0x100000000-x)
    if x<2147483648:
      return -x
    else:
      return -2147483648
  return x

def int32_s(x):
    return str(int32(x))

def imm_s(x):
    return '#'+int32_s(x)

def reg(x):
    return 'r'+str(x)

def o(off):
    if off <= 32767:
        return "+" + str(off)
    else:
        return "-" + str(65536-off)

def mem(base, off):
    if off != 0:
        return "[%s%s]" % (base, o(off))
    else:
        return "[%s]" % base

def _format_byte(byte):
    line = struct.pack('Q', byte).encode('hex')
    return ' '.join([line[i:i+2] for i in range(0, len(line), 2)])

def _format_id(_id):
    return '0x{:04x}'.format(_id)

def F_I(_id, bytes, opcode, dst="", src="", offset=""):
    if dst != "" and src != "":
        dst += ','
    if offset != "":
        src += ','
    return "{}:   {:28} {:10}{:10}{:5}{}\n".format(_format_id(_id), _format_byte(bytes), opcode, dst, src, offset)

# msb                                                        lsb
# +------------------------+----------------+----+----+--------+
# |immediate               |offset          |src |dst |opcode  |
# +------------------------+----------------+----+----+--------+

def parse_instruction(instr, _id = 0):

    #print "INSTR", struct.pack('Q', instr)[::-1].encode('hex')

    try:
        instr = struct.unpack('Q',instr)[0]
    except:
        return ""

    opcode = (instr & 0x00000000000000ff) >> 0
    dest   = (instr & 0x0000000000000f00) >> 8
    src    = (instr & 0x000000000000f000) >> 12
    offset = (instr & 0x00000000ffff0000) >> 16
    imm    = (instr & 0xffffffff00000000) >> 32

    _class = opcode & 0x7

    if _class == BPF_ALU or _class == BPF_ALU64:
        # msb      lsb
        #  0000 0 000
        # +----+-+---+
        # |op  |s|cls|
        # +----+-+---+
        # If the s bit is zero, then the source operand is imm. If s is one,
        # then the source operand is src. The op field specifies which ALU or
        # branch operation is to be performed.
        _s  = opcode & 0x08
        _op = opcode & 0xf0
        suffix = ''
        if _class == BPF_ALU:
            suffix = '32'
        if _op in ALU:
            if _op == 0x80:
                return F_I(_id, instr, ALU[_op] + suffix, reg(dest))
            if _s == 0: # imm
                return F_I(_id, instr, ALU[_op] + suffix, reg(dest), imm_s(imm))
            else: # src
                return F_I(_id, instr, ALU[_op] + suffix, reg(dest), reg(src))

    if _class == BPF_JMP:
        # msb      lsb
        #  0000 0 000
        # +----+-+---+
        # |op  |s|cls|
        # +----+-+---+
        # If the s bit is zero, then the source operand is imm. If s is one,
        # then the source operand is src. The op field specifies which ALU or
        # branch operation is to be performed.
        _s  = opcode & 0x08
        _op = opcode & 0xf0
        if _op in JMP:
            ins = JMP[_op]
            if ins == "exit": # exit
                return F_I(_id, instr, ins)
            if ins == "call": # call
                return F_I(_id, instr, ins, imm_s(imm))
            if _s == 0: # imm
                return F_I(_id, instr, ins, reg(dest), imm_s(imm), o(offset))
            else: # src
                return F_I(_id, instr, ins, reg(dest), reg(src), o(offset))
    if _class in [BPF_LD, BPF_LDX, BPF_ST, BPF_STX]:
        # msb      lsb
        #  000 00 000
        # +---+--+---+
        # |mde|sz|cls|
        # +---+--+---+
        _sz  = opcode & 0x18
        _mde = opcode & 0xe0
        #print hex(opcode), hex(_mde), hex(_sz)
        if _mde in LDS:
            if _sz in SIZES:
                mode = LDS[_mde]
                #print hex(_class), hex(opcode), hex(_mde)
                if mode == "mem" or mode == "imm":
                    mode_s = ""
                else:
                    mode_s = mode
                if _class == BPF_LD:
                    return F_I(_id, instr, 'ld' + mode_s + SIZES[_sz],reg(src), reg(dest), imm_s(imm))
                elif _class == BPF_LDX:
                    return F_I(_id, instr, 'ldx' + mode_s  + SIZES[_sz], reg(dest), mem(reg(src), offset))
                elif _class == BPF_ST:
                    return F_I(_id, instr, 'st' + mode_s + SIZES[_sz], mem(reg(dest), offset), imm_s(imm))
                elif _class == BPF_STX:
                    return F_I(_id, instr, 'stx' + mode_s + SIZES[_sz], mem(reg(dest), offset), reg(src))
    if _class == BPF_RET:
        return F_I(_id, instr, 'ret', imm_s(imm))

    return "(Invalid instruction)" + struct.pack('Q', instr)[::-1].encode('hex')

def decompile(raw_bytes):
    out = ""
    if raw_bytes[-1] == '\n':
        raw_bytes = raw_bytes[:-1]
    if len(raw_bytes) % (SIZE/8) != 0:
        print "Invalid program length"
        #sys.exit(1)

    p_instructions = [raw_bytes[i:i+SIZE/8] for i in range(0, len(raw_bytes), SIZE/8)]

    for i, ins in enumerate(p_instructions):
        out += parse_instruction(ins, i)

    return out.strip()


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print "Usage: {} program.bin ".format(sys.argv[0])
        sys.exit(1)

    p = open(sys.argv[1],'rb').read()

    print decompile(p)

