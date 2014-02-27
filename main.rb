class Instruction
  attr_accessor :operator, :dest, :src, :modrm, :op_en

  def initialize( operator, dest, src,  op_en, modrm)
     #/digit A digit between 0 and 7 indicates to use only the r/m operand. The reg field provides an extension to the instruction's opcode.
    #/r — Indicates that the ModR/M byte of the instruction contains a register operand and an r/m operand.
    #+rd, +ro — A register code, from 0 through 7, added to the hexadecimal byte given at the left of the plus sign to form a single opcode byte. See Table 3-1 for the codes.
    #+i — The number i (which can range from 0 to 7) is added to the hexadecimal byte given at the left of the plus sign to form a single opcode byte.
    #ib, iw and id indicate that one of the operands to the instruction is an immediate value, and that this is to be encoded as a byte,
    @op_en = op_en

    # for instance: add, nop, and, not, bswap, or, call, pop, cmp, popcnt, dec, push, idiv, repne, cmpsd, imul
    # retf, inc, retn, jmp, sal, jz/jnz, sar, lea, sbb, mov, shl, movsb/movsd, shr, movzx, test,  mul, xor, neg
    @operator = operator

    #imm8 — An immediate byte value. The imm8 symbol is a signed number between –128 and +127 inclusive. The upper byte of the word is filled with the topmost bit of the immediate value.
    #imm32 — An immediate doubleword value used for instructions whose operand-size attribute is 32 bits. It allows the use of a number between +2,147,483,647 and –2,147,483,648 inclusive.
    #r32 — One of the doubleword general-purpose registers: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI;
    #r/m32 — A doubleword general-purpose register or memory operand used for instructions whose operandsize attribute is 32 bits.
    #The doubleword general-purpose registers are: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI.
    #The contents of memory are found at the address provided by the effective address computation.

    # The source and destination fields
    @src = src
    @dest = dest

    #true/false value to determine whether modrm is used in regular case
    @modrm = modrm
  end
end

@instructions = {}

# add
@instructions['05'] = Instruction.new 'ADD', 'EAX', 'imm32', '/d', false
@instructions['01'] = Instruction.new 'ADD', 'r/m', 'r', '/r', true
@instructions['03'] = Instruction.new 'ADD', 'r', 'r/m', '/r', true


