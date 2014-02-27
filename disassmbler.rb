require './main.rb'
require './methods.rb'

def disassemble instruction_address
  #get opcode of next byte to be disassembled
  opcode = @hex[instruction_address]
  if @special_cases.include?(opcode)
    return special_case opcode, instruction_address
  end
  # if call or jmp
  if @jump_opcodes.include?(opcode)
    return jumps opcode, instruction_address
  end
  # if instruction a single byte instruction then call single byte
  if @single_byte_opcodes.include?(opcode)
    return single_byte opcode, instruction_address
  end
  # if instruction is extended (meaning /number with opcode) then call extended opcode
  if @extended_opcodes.include?(opcode)
    return extended_opcodes opcode, instruction_address
  end
  #if multibyte opcode
  if @multibyte_opcodes.include?(opcode)
    return multibyte_opcodes opcode, instruction_address
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
  location = "#{address_location.to_i.to_s(16)}:".ljust(10)
  if @labels.include?(location.split(':').first)
    puts "Label_0x#{location}"
  end
  if !ins.nil?
    address = hex.ljust(40)
    instruction = ins.first.ljust(40)
    puts "#{location}#{address}#{instruction}"
  else
    instruction = "#{@hex[@counter - 1]}".ljust(40)
    puts "#{location}#{instruction}invalid instruction "
  end
end


