#set up columns for table 2-2 page 33 64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
@zz_column_eax = %w(00 01 02 03 04 05 06 07)
@zz_column_ecx = %w(08 09 0a 0b 0c 0d 0e 0f)
@zz_column_edx = %w(10 11 12 13 14 15 16 17)
@zz_column_ebx = %w(18 19 1a 1b 1c 1d 1e 1f)
@zz_column_esp = %w(20 21 22 23 24 25 26 27)
@zz_column_ebp = %w(28 29 2a 2b 2c 2d 2e 2f)
@zz_column_esi = %w(30 31 32 33 34 35 36 37)
@zz_column_edi = %w(38 39 3a 3b 3c 3d 3e 3f)

@zz = [@zz_column_eax, @zz_column_ecx, @zz_column_edx, @zz_column_ebx, @zz_column_esp, @zz_column_ebp, @zz_column_esi, @zz_column_edi]

@zo_column_eax = %w(40 41 42 43 44 45 46 47)
@zo_column_ecx = %w(48 49 4a 4b 4c 4d 4e 4f)
@zo_column_edx = %w(50 51 52 53 54 55 56 57)
@zo_column_ebx = %w(58 59 5a 5b 5c 5d 5e 5f)
@zo_column_esp = %w(60 61 62 63 64 65 66 67)
@zo_column_ebp = %w(68 69 6a 6b 6c 6d 6e 6f)
@zo_column_esi = %w(70 71 72 73 74 75 76 77)
@zo_column_edi = %w(78 79 7a 7b 7c 7d 7e 7f)

@zo = [@zo_column_eax, @zo_column_ecx, @zo_column_edx, @zo_column_ebx, @zo_column_esp, @zo_column_ebp, @zo_column_esi, @zo_column_edi]

@oz_column_eax = %w(80 81 82 83 84 85 86 87)
@oz_column_ecx = %w(88 89 8a 8b 8c 8d 8e 8f)
@oz_column_edx = %w(90 91 92 93 94 95 96 97)
@oz_column_ebx = %w(98 99 9a 9b 9c 9d 9e 9f)
@oz_column_esp = %w(a0 a1 a2 a3 a4 a5 a6 a7)
@oz_column_ebp = %w(a8 a9 aa ab ac ad ae af)
@oz_column_esi = %w(b0 b1 b2 b3 b4 b5 b6 b7)
@oz_column_edi = %w(b8 b9 ba bb bc bd be bf)

@oz = [@oz_column_eax, @oz_column_ecx, @oz_column_edx, @oz_column_ebx, @oz_column_esp, @oz_column_ebp, @oz_column_esi, @oz_column_edi]

@oo_column_eax = %w(c0 c1 c2 c3 c4 c5 c6 c7)
@oo_column_ecx = %w(c8 c9 ca cb cc cd ce cf)
@oo_column_edx = %w(d0 d1 d2 d3 d4 d5 d6 d7)
@oo_column_ebx = %w(d8 d9 da db dc dd de df)
@oo_column_esp = %w(e0 e1 e2 e3 e4 e5 e6 e7)
@oo_column_ebp = %w(e8 e9 ea eb ec ed ee ef)
@oo_column_esi = %w(f0 f1 f2 f3 f4 f5 f6 f7)
@oo_column_edi = %w(f8 f9 fa fb fc fd fe ff)

@oo = [@oo_column_eax, @oo_column_ecx, @oo_column_edx, @oo_column_ebx, @oo_column_esp, @oo_column_ebp, @oo_column_esi, @oo_column_edi]

@operand = %w(EAX ECX EDX EBX ESP EBP ESI EDI)
@instructions = {}
@single_byte_opcodes = []
@extended_opcodes = []
@multibyte_opcodes = []
@jump_opcodes = []
@labels = []

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


# add 05 81 01 03
@instructions['05'] = Instruction.new 'ADD', 'EAX', 'imm32', '/d', false
@instructions['01'] = Instruction.new 'ADD', 'r/m', 'r', '/r', true
@instructions['03'] = Instruction.new 'ADD', 'r', 'r/m', '/r', true
@extended_opcodes << '81'
#nop 90
@single_byte_opcodes << '90'
#and 25 81 21 23
@instructions['25'] = Instruction.new 'AND', 'EAX', 'imm32', '/d', false
@instructions['21'] = Instruction.new 'AND', 'r/m', 'r', '/r', true
@instructions['23'] = Instruction.new 'AND', 'r', 'r/m', '/r', true
#not f7
@extended_opcodes << 'f7'
#bswap
@multibyte_opcodes << '0f'
#or 0d 81 09 0b
@instructions['0d'] = Instruction.new 'OR', 'EAX', 'imm32', '/d', false
@instructions['09'] = Instruction.new 'OR', 'r/m', 'r', '/r', true
@instructions['0b'] = Instruction.new 'OR', 'r', 'r/m', '/r', true
#call e8
@jump_opcodes << 'e8'
#pop 8f 58
@extended_opcodes << '8f'
@single_byte_opcodes << '58' << '59' << '5a' << '5b' << '5c' << '5d' << '5e' << '5f'
#cmp 3d 81 39 3b
@instructions['3d'] = Instruction.new 'CMP', 'EAX', 'imm32', '/d', false
@instructions['39'] = Instruction.new 'CMP', 'r/m', 'r', '/r', true
@instructions['3b'] = Instruction.new 'CMP', 'r', 'r/m', '/r', true


