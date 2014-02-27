require './main.rb'
require './methods.rb'

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

# set up single byte opcode list
@single_byte_opcodes = %w(50 51 52 53 54 55 56 57 48 49 4a 4b 4c 4d 4e 4f 58 59 5a 5b 5c 5d 5e 5f b8 b9 ba bb bc bd be bf)
@extended_opcodes = %w(81 FF)

def disassemble instruction_address
  #get opcode of next byte to be disassembled
  opcode = @hex[instruction_address]
  # if instruction a single byte instruction then call single byte
  if @single_byte_opcodes.include?(opcode)
    return single_byte opcode, instruction_address
  end
  # if instruction is extended (meaning /number with opcode) then call extended opcode
  if @extended_opcodes.include?(opcode)
    return extended_opcodes opcode, instruction_address
  end
  # if we have an instruction for it
  if !@instructions[opcode].nil?
    # if EAX is the value of either one of the src or dest then call default EAX
    if @instructions[opcode].src == "EAX" or @instructions[opcode].dest == "EAX"
      return default_eax opcode, instruction_address
    else
      # if instruction is encoded regular modrm call modrm
      return decode_modrm instruction_address, opcode, nil
    end
  end

end

def decode_modrm instruction_address, opcode, operator_override
  operands = @bits[instruction_address + 1]
  mod = operands[0..1]
  modrm = @hex[instruction_address + 1]
  instruction = @instructions[opcode]
  operator = instruction.operator
  case mod
    when '00'
      @zz.each_with_index do |column, i|
        if column.include?(modrm) and instruction.dest == 'r/m' and instruction.src == 'r' # if add r/m32, r32  = 01/r
          index = column.index(modrm)
          if index == 5 # this is a memory reference not register test with add (01 05 78 56 34 12) should be [0x12345678], eax
            mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}"
            return ["#{operator} \t[0x#{mem}],#{@operand[i]}", true, 6]
          else
            return ["#{operator} \t[#{@operand[index]}], #{@operand[i]}", true, 2] # test with add (01 30) should be add [eax], esi
          end
        end
        if column.include?(modrm) and instruction.dest == 'r' and instruction.src = 'r/m' # if add r32, r/m32 = 03/r
          index = column.index(modrm)
          if index == 5 # this is a memory reference not register test with add (03 05 78 56 34) should be add eax, [0x12345678]
            mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}"
            return ["#{operator} \t#{@operand[i]}, [0x#{mem}]", true, 6]
          else
            return ["#{operator} \t#{@operand[i]}, [#{@operand[index]}]", true, 2] # test with add (01 06) should be add [esi], eax
          end
        end
      end
    when '01'
      @zo.each_with_index do |column, i|
        if column.include?(modrm) and instruction.dest == 'r/m' and instruction.src == 'r' # if add r/m32, r32  = 01/r
          index = column.index(modrm)
          mem = "#{@hex[instruction_address + 2]}"
          return ["#{operator} \t[#{@operand[index]}+0x#{mem}], #{@operand[i]}", true, 3]#test with add (01 40 78) should be add [eax+0x78], eax
        end
        if column.include?(modrm) and instruction.dest == 'r' and instruction.src = 'r/m' # if add r32, r/m32 = 03/r
          index = column.index(modrm)
          mem = "#{@hex[instruction_address + 2]}"
          return ["#{operator} \t#{@operand[i]}, [#{@operand[index]}+0x#{mem}]", true, 3]# test with add (03 40 78) should be add eax,[eax+0x78]
        end
      end
    when '10'
      @oz.each_with_index do |column, i|
        if column.include?(modrm) and instruction.dest == 'r/m' and instruction.src == 'r' # if add r/m32, r32  = 01/r
          index = column.index(modrm)
          mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}"
          return ["#{operator} \t[#{@operand[index]}+0x#{mem}], #{@operand[i]}", true, 6]#test with add (01 80 78 56 34 12) should be add [eax+0x12345678], eax
        end
        if column.include?(modrm) and instruction.dest == 'r' and instruction.src = 'r/m' # if add r32, r/m32 = 03/r
          index = column.index(modrm)
          # test with add (03 8a 90 78 56 34) should be ADD ECX, [EDX+0x34567890]
          mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}"
          return ["#{operator} \t#{@operand[i]}, [#{@operand[index]}+0x#{mem}]", true, 6]
        end
      end
    when '11'
      @oo.each_with_index do |column, i|
        if column.include?(modrm) and instruction.dest == 'r/m' and instruction.src == 'r' # if add r32, r/m32  = 01/r
          index = column.index(modrm)
          return ["#{operator} \t#{@operand[index]}, #{@operand[i]}", true, 2]#test with add (01 dc) should be add esp, ebx
        end
        if column.include?(modrm) and instruction.dest == 'r' and instruction.src = 'r/m' # if add r32, r/m32 = 03/r
          index = column.index(modrm)
          # test with add (03 c0) should be ADD eax, eax
          return ["#{operator} \t#{@operand[i]}, #{@operand[index]}", true, 6]
        end
      end
  end
  return["Invalid opcode:#{opcode}", false, 1]
end


##############################################################################################################
#Linear Sweep Algorithm
##############################################################################################################
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
@labels = []

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


