# handles the special cases of default EAX in one of the src or dest
def default_eax opcode, instruction_address
  case opcode
    #handle ADD EAX, Imm32

    when '05'
      mem = "0x#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}#{@hex[instruction_address + 1]}"
      return ["ADD \tEAX, #{mem}", true, 5]
  end
  return["Invalid opcode:#{opcode}", false, 1]
end

def extended_opcodes opcode, instruction_address
  operands = @bits[instruction_address + 1]
  mod = operands[0..1]
  reg = operands[2..4]
  rm = operands[5..7]
  modrm = @hex[instruction_address + 1]
  operator = ''
  case opcode
    when '81'
      case reg
        when '000'
          operator = 'ADD'
      end
      case mod #seven possibilities 000 - 111 for r/m
        when '00'
          @zz.each_with_index do |column, i|
            if column.include?(modrm)
              index = column.index(modrm)
              if index == 5
                mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}"
                next_mem = "#{@hex[instruction_address + 9]}#{@hex[instruction_address + 8]}#{@hex[instruction_address + 7]}#{@hex[instruction_address + 6]}"
                return ["#{operator} \t[0x#{mem}], 0x#{next_mem}", true, 10] # format should be operator [next 4 bytes of mem], next four bytes of mem: test 81 05 44 33 22 11 88 77 66 55 = add [11223344], 55667788
              else
                mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}"
                return ["#{operator} \t[#{@operand[index]}], 0x#{mem}", true, 6] # format should be operator [reg], next 4 bytes: test with 81 00 44 33 22 11 = add [eax], 11223344
              end
            end
          end
        when '01'
          @zo.each_with_index do |column, i|
            if column.include?(modrm)
              index = column.index(modrm)
              mem = "#{@hex[instruction_address + 2]}"
              next_mem = "#{@hex[instruction_address + 6]}#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}"
              return ["#{operator} \t[#{@operand[index]}+0x#{mem}], 0x#{next_mem}", true, 7] # format should be operator [reg+1byte], next 4 bytes: test with 81 40 08 44 33 22 11 = add [eax+0x08], 0x11223344
            end
          end
        when '10'
          @oz.each_with_index do |column, i|
            if column.include?(modrm)
              index = column.index(modrm)
              mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}"
              next_mem = "#{@hex[instruction_address + 9]}#{@hex[instruction_address + 8]}#{@hex[instruction_address + 7]}#{@hex[instruction_address + 6]}"
              return ["#{operator} \t[#{@operand[index]}+0x#{mem}], 0x#{next_mem}", true, 10] # format should be operator [reg+1byte], next 8 bytes: test with 81 80 44 33 22 11 88 77 66 55 = add dword [eax+0x11223344], 0x55667788
            end
          end
        when '11'
          @oo.each_with_index do |column, i|
            if column.include?(modrm)
              index = column.index(modrm)
              mem = "#{@hex[instruction_address + 5]}#{@hex[instruction_address + 4]}#{@hex[instruction_address + 3]}#{@hex[instruction_address + 2]}"
              return ["#{operator} \t#{@operand[index]}, 0x#{mem}", true, 6] # format should be operator [reg+8bytes], next 8 bytes: test with 81 C0 44 33 22 11 = add eax, 0x11223344
            end
          end
      end
  end
  return ["extended opcodes, nothing caught", false, 1]
end





