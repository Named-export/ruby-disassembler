class Instruction
  attr_accessor :opcode, :operator, :has_operand, :src, :dest, :modrm, :op_en

  def initialize(opcode, op_en, operator, has_operand, src, dest, modrm)
    @opcode = opcode

    #/digit A digit between 0 and 7 indicates to use only the r/m operand. The reg field provides an extension to the instruction's opcode.
    #/r — Indicates that the ModR/M byte of the instruction contains a register operand and an r/m operand.
    #+rd, +ro — A register code, from 0 through 7, added to the hexadecimal byte given at the left of the plus sign to form a single opcode byte. See Table 3-1 for the codes.
    #+i — The number i (which can range from 0 to 7) is added to the hexadecimal byte given at the left of the plus sign to form a single opcode byte.
    #ib, iw and id indicate that one of the operands to the instruction is an immediate value, and that this is to be encoded as a byte,
    @op_en = op_en


    @operator = operator
    @has_operand = has_operand

    #imm8 — An immediate byte value. The imm8 symbol is a signed number between –128 and +127 inclusive. The upper byte of the word is filled with the topmost bit of the immediate value.
    #imm32 — An immediate doubleword value used for instructions whose operand-size attribute is 32 bits. It allows the use of a number between +2,147,483,647 and –2,147,483,648 inclusive.
    #r32 — One of the doubleword general-purpose registers: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI;
    #r/m32 — A doubleword general-purpose register or memory operand used for instructions whose operandsize attribute is 32 bits.
    #The doubleword general-purpose registers are: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI.
    #The contents of memory are found at the address provided by the effective address computation.

    @src = src
    @dest = dest

    @modrm = modrm
  end
end
@instructions = {}
#xor                                  opcode, op_en, operator, has_operand, src, dest, modrm
@instructions['31'] = Instruction.new '31', '/r', 'XOR', true, 'r', 'r/m', true
@instructions['33'] = Instruction.new '33', '/r', 'XOR', true, 'r/m', 'r', true
@instructions['81'] = Instruction.new '81', '/6/d', 'XOR', true, 'r/m', 'imm32', false
@instructions['35'] = Instruction.new '35', '/d', 'XOR', true, 'EAX', 'imm32', false


#push                                 opcode, op_en, operator, has_operand, src, dest, modrm
@push = %w(50 51 52 53 54 55 56 57)
@instructions['ff'] = Instruction.new 'FF', '/6', 'PUSH', false, 'r/m', 'stack', true
#@instructions['50'] = Instruction.new '50', '+rd', 'PUSH', false, 'rm', 'stack', true
@instructions['68'] = Instruction.new '68', '/d', 'PUSH', false, 'r/m', 'stack', true

#dec
@dec = %w(48 49 4a 4b 4c 4d 4e 4f)
@instructions['ff'] = Instruction.new 'FF', '/1', 'PUSH', false, 'r/m', 'stack', true

#pop
@pop = %w(58 59 5a 5b 5c 5d 5e 5f)
@instructions['8f'] = Instruction.new '8f', '/0', 'POP', false, 'r/m', 'stack', true
#@instructions['58'] = Instruction.new '58', '+rd', 'POP', false, 'r/m', 'stack', true

#mov                                  opcode, op_en, operator, has_operand, src, dest, modrm
@mov = %w(b8 b9 ba bb bc bd be bf)
@instructions['89'] = Instruction.new '89', '/r', 'MOV', true, 'r', 'r/m', true
@instructions['8b'] = Instruction.new '8b', '/r', 'MOV', true, 'r/m', 'r', true
#@instructions['B8'] = Instruction.new 'B8', '+rd/d', 'MOV', true, 'imm32', 'r32', true
@instructions['c7'] = Instruction.new 'C7', '/0id', 'MOV', true, 'imm32', 'r/m', true
@instructions['a1'] = Instruction.new 'a1', '', 'MOV', true, 'moffs', 'EAX', true

#ret                                  opcode, op_en, operator, has_operand, src, dest, modrm
@ret = %w(c2 c3 ca cb)
@instructions['c3'] = Instruction.new 'c3', '', 'RET', true, 'r', 'r/m', false
@instructions['cb'] = Instruction.new 'cb', '', 'RET', true, 'r', 'r/m', false
@instructions['c2'] = Instruction.new 'c2', '/w', 'RET', true, 'r', 'r/m', false
@instructions['ca'] = Instruction.new 'ca', '/w', 'RET', true, 'r', 'r/m', false

#nop does not handle multi byte nop
@nop = %w(90)

#and
@instructions['25'] = Instruction.new '25', '/d', 'AND', true, 'imm32', 'EAX', false
@instructions['81'] = Instruction.new '81', '/4', 'AND', true, 'imm32', 'r/m', false
@instructions['21'] = Instruction.new '21', '/r', 'AND', true, 'r', 'r/m', false
@instructions['23'] = Instruction.new '23', '/r', 'AND', true, 'r/m', 'r', false

@not = %w(f7)
@bswap = %w(0f)
@call = %w(e8)
@popcnt = %w(f3)
@instructions['f3'] = Instruction.new 'f3', '/r', 'POPCNT', true, 'r', 'r/m', false


#or
@instructions['0d'] = Instruction.new '0d', '/d', 'OR', true, 'imm32', 'EAX', false
@instructions['81'] = Instruction.new '81', '/1', 'OR', true, 'imm32', 'r/m', false
@instructions['09'] = Instruction.new '09', '/r', 'OR', true, 'r', 'r/m', false
@instructions['0b'] = Instruction.new '0b', '/r', 'OR', true, 'r/m', 'r', false

#cmp
@instructions['3d'] = Instruction.new '3d', '/d', 'CMP', true, 'imm32', 'EAX', false
@instructions['81'] = Instruction.new '81', '/7', 'CMP', true, 'imm32', 'r/m', false
@instructions['39'] = Instruction.new '39', '/r', 'CMP', true, 'r', 'r/m', false
@instructions['3b'] = Instruction.new '3b', '/r', 'CMP', true, 'r/m', 'r', false


@registers = {}
@registers['000'] = 'EAX'
@registers['001'] = 'ECX'
@registers['010'] = 'EDX'
@registers['011'] = 'EBX'
@registers['100'] = 'ESP'
@registers['101'] = 'EBP'
@registers['110'] = 'ESI'
@registers['111'] = 'EDI'

#add                                  opcode, op_en, op, has_operand, src, dest, modrm
@add = %w(05 81 01 03)
@instructions['05'] = Instruction.new '05', '/d', 'ADD', true, 'imm32', 'EAX', false
@instructions['81'] = Instruction.new '81', '/0/d', 'ADD', true, 'imm32', 'r/m', false
@instructions['01'] = Instruction.new '01', '/r', 'ADD', true, 'r/m', 'r', true
@instructions['03'] = Instruction.new '03', '/r', 'ADD', true, 'r/m', 'r', true

@labels = []


def disassemble instruction_address
  # get opcode from hex array
  opcode = @hex[instruction_address]

  if @push.include?(opcode)
    #its a +rd push operation
    instruction = (opcode.to_i - 50).to_s(2)
    while instruction.length !=3
      instruction.to_s.insert(0, '0')
    end
    return ["PUSH \t#{@registers[instruction]}", true, 1]
  elsif @mov.include?(opcode)
    #its a +rd mov operation
    instruction = (opcode.hex - 184).to_s(2)
    while instruction.length !=3
      instruction.to_s.insert(0, '0')
    end
    #take next 4 bytes
    mem = "#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}#{@hex[instruction_address + 1]}h"
    return ["MOV \t#{@registers[instruction]}, #{mem}", true, 5]
  elsif @pop.include?(opcode)
    #its a +rd pop operation
    instruction = (opcode.hex - 88).to_s(2)
    while instruction.length !=3
      instruction.to_s.insert(0, '0')
    end
    return ["POP \t#{@registers[instruction]}", true, 1]
  elsif @ret.include?(opcode)
    # its a ret
    if @instructions[opcode].op_en == '/w'
      return ["RET \t#{@hex[instruction_address + 1]}h", true, 2]
    else
      return ['RET', true, 1]
    end
  elsif @nop.include?(opcode)
    # its a nop
    if opcode == @nop.first
      return ['NOP', true, 1]
    end
  elsif @not.include?(opcode)
    operands = @bits[instruction_address + 1]
    mod = operands[0..1]
    reg = operands[2..4]
    rm = operands[5..7]
    if reg == '111' #idiv
      case mod
      when '00'
        return ["IDIV \t[#{@registers[rm]}]", true, 2]
      when '11'
        return ["IDIV \t#{@registers[rm]}", true, 2]
    end
    elsif reg == '101'
      case mod
        when '00'
          return ["IMUL \t[#{@registers[rm]}]", true, 2]
        when '11'
          return ["IMUL \t#{@registers[rm]}", true, 2]
      end
    else
    case mod #not
      when '00'
        return ["NOT \t[#{@registers[rm]}]", true, 2]
      when '11'
        return ["NOT \t#{@registers[rm]}", true, 2]
    end
    end
  elsif @bswap.include?(opcode)
    operand = @hex[instruction_address + 1]
    instruction = (operand.hex - 200).to_s(2)
    while instruction.length !=3
      instruction.to_s.insert(0, '0')
    end
    return ["BSWAP #{@registers[instruction]}", true, 2]
  elsif @call.include?(opcode)
    #take starting address plus 0x5 (length of instruction) + value in next 4 bytes
    mem = "#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}#{@hex[instruction_address + 1]}".hex
    address = instruction_address.to_i + 5 + mem
    @labels << address.to_s(16)
    return ["CALL \tLabel_0x#{address.to_s(16)}", true, 5]
  elsif @popcnt.include?(opcode)
    operands = @bits[instruction_address + 3]
    mod = operands[0..1]
    reg = operands[2..4]
    rm = operands[5..7]
    case mod
      when '00'
        return ["POPCNT #{@registers[reg]},[#{@registers[rm]}]", true, 4]
      when '11'
        return ["POPCNT #{@registers[reg]},#{@registers[rm]}", true, 4]
    end
  elsif @dec.include?(opcode)
    #its a +rd pop operation
    instruction = (opcode.hex - 72).to_s(2)
    while instruction.length !=3
      instruction.to_s.insert(0, '0')
    end
    return ["DEC \t#{@registers[instruction]}", true, 1]
  elsif !@instructions[opcode].nil?
    instruction = @instructions[opcode]
    operands = @bits[instruction_address + 1]
    mod = operands[0..1]
    if !instruction.op_en.match(/\/[0-7]/).nil? # special case where reg of modrm is set by opcode
      reg = instruction.op_en.match(/\/[0-7]/).to_s.split('/').last
      while reg.length !=3
        reg.to_s.insert(0, '0')
      end
      rm = operands[5..7]
                                                #puts "reg = #{reg} rm = #{rm}"
    elsif instruction.op_en.include?('/r') # reg and rm are set by reg values
      reg = operands[2..4]
      rm = operands[5..7]
    elsif instruction.op_en == '' and instruction.src == 'moffs' # no special instruction
      reg = instruction.dest
      mem = "#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}#{@hex[instruction_address + 1]}h]"
      return ["#{instruction.operator} \t#{reg}, [#{mem}", true, 5]
    elsif instruction.op_en == '/d'
      if instruction.dest == 'EAX'
        reg = '000'
        mem = "#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}#{@hex[instruction_address + 1]}h"
        return ["#{instruction.operator} \t#{@registers[reg]}, #{mem}", true, 5]
      end
    end
    case mod
      when '00'
        if instruction.src == 'r' and instruction.dest == 'r/m'
          if rm == '101'
            mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}h"
            return ["#{instruction.operator} \t#{mem}, #{@registers[reg]}", true, 4]
          end
          return ["#{instruction.operator} \t[#{@registers[rm]}], #{@registers[reg]}", true, 2]
        elsif instruction.src == 'r/m' and instruction.dest == 'r'
          if rm == '101'
            mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}h"
            return ["#{instruction.operator} \t#{@registers[reg]}, [#{mem}]", true, 6]
          end
          return ["#{instruction.operator} \t#{@registers[rm]}, [#{@registers[reg]}]", true, 2]
        elsif instruction.src == 'imm32' and instruction.dest == 'r/m'
          mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}h"
          if rm == '101'
            imm = "#{@hex[instruction_address + 9]}#{@hex[instruction_address + 8]}#{@hex[instruction_address + 7]}#{@hex[instruction_address + 6]}h"
            return ["#{instruction.operator} \t[#{mem}], #{imm}", true, 10]
          end
          return ["#{instruction.operator} \t[#{@registers[rm]}], #{mem}", true, 6]
        end
      when '01'
        if instruction.src == 'r' and instruction.dest == 'r/m'
          mem = @hex[instruction_address + 2]
          return ["#{instruction.operator} \t[#{@registers[rm]} + #{mem}h], #{@registers[reg]}", true, 3]
        elsif instruction.src == 'r/m' and instruction.dest == 'r'
          mem = @hex[instruction_address + 2]
          return ["#{instruction.operator} \t#{@registers[reg]}, [#{@registers[rm]} + #{mem}h]", true, 3]
        end
      when '10'
        mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}h"
        if instruction.src == 'imm32' and instruction.dest == 'r/m'
          imm = "#{@hex[instruction_address + 9]}#{@hex[instruction_address + 8]}#{@hex[instruction_address + 7]}#{@hex[instruction_address + 6]}h"
          return ["#{instruction.operator} \t[#{@registers[reg]} + #{mem}], #{imm}", true, 10]
        elsif instruction.src == 'r' and instruction.dest == 'r/m'
          return ["#{instruction.operator} \t[#{@registers[rm]} + #{mem}], #{@registers[reg]}", true, 6]
        elsif instruction.src == 'r/m' and instruction.dest == 'r'
          return ["#{instruction.operator} \t[#{@registers[rm]} + #{mem}], #{@registers[reg]}", true, 6]
        end
      when '11'
        return ["#{instruction.operator} \t#{@registers[rm]}, #{@registers[reg]}", true, 2]
    end
  else
    return ["No instruction opcode #{opcode}, address #{instruction_address.to_i.to_s(16)}", false, 1] if instruction.nil?
  end
end


# step one: read in binary file contents
begin
  @file_contents = File.binread("#{ARGV.first}")
rescue Exception => ex
  puts "There was an error trying to open your input file: #{ex}"
  puts "Exception backtrace: #{ex.backtrace.inspect}"
end
# step two: get hex and place each byte into the array hex
begin
  @hex = @file_contents.unpack('H*')[0].scan(/.{2}/)
rescue Exception => ex
  puts "There was an error trying to convert binary into hexadecimal: #{ex}"
  puts "Exception backtrace: #{ex.backtrace.inspect}"
end
begin
  @bits = @file_contents.unpack('B*')[0].scan(/.{8}/)
rescue Exception => ex
  puts "There was an error trying to convert file contents into binary: #{ex}"
  puts "Exception backtrace: #{ex.backtrace.inspect}"
end
# step three: begin linear sweep
puts @hex.inspect
puts @bits.inspect
@counter = 0

while @counter != @hex.length
  address_location = @counter
  hex = ''
  ins = disassemble @counter
  #if instruction is valid
  if !ins.nil? and ins[1] == true
    #increment by size of the instruction
    ins.last.times do |x|
      hex << @hex[@counter + x] + ' '
    end
    @counter += ins.last
  else
    #increment by 1
    @counter += 1
  end
  if !ins.nil?
    location = "#{address_location.to_i.to_s(16)}:".ljust(10)
    address = hex.ljust(40)
    instruction = ins.first.ljust(20)
    if @labels.include?(location.split(':').first)
      puts "Label_0x#{location}"
    end
    puts "#{location}#{address}#{instruction}"
  else
    puts "invalid instruction"
  end
end



