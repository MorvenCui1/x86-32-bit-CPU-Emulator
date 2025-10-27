from capstone import *
from capstone.x86 import *

#x86 instructions to run
code = bytes.fromhex('b8 0A 00 00 00 bb 02 00 00 00 03 c3')

assert code is not None #Checks if code is empty at start

cs = Cs(CS_ARCH_X86, CS_MODE_32) #Disassembly engine setup for x86 32-bit
cs.detail = True #Provide detailed information about each instruction
cs.skipdata = True #Skip over unreadable data

#CPU Registers
registers = {}
registers[X86_REG_EAX] = 0
registers[X86_REG_EBX] = 0
registers[X86_REG_EDX] = 0

#EIP is instruction pointer
#Set it to beginning of code
registers[X86_REG_EIP] = 0

#Set reset pin to initially false
reset = False

#While instruction pointer has not reached end of code yet
while registers[X86_REG_EIP] != len(code):
    if reset: #If reset is true set all registers back to initial value
        registers[X86_REG_EAX] = 0
        registers[X86_REG_EBX] = 0
        registers[X86_REG_EDX] = 0
        reset = False

    address = registers[X86_REG_EIP] #Variable to hold current instruction pointer

    #Take next instructions for length of up to maximum length of 16 bits
    instruction = next(cs.disasm(code[address:address+15], address))
    mnemonic = instruction.mnemonic
    operands = instruction.operands

    #Debug print
    print(f"{address:#010x}:\t{instruction.mnemonic}\t{instruction.op_str}")

    #Move command
    if mnemonic == "mov":
        #Move immediate value to register
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            registers[operands[0].reg] = operands[1].value.imm

            print(f"Register: {registers[operands[0].reg]}")
        #Move value from one register to another
        elif operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            registers[operands[0].reg] = registers[operands[1].reg]

            print(f"Register: {registers[operands[0].reg]}")
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break
    #Add command
    elif mnemonic == "add":
        #Add values in two registers
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            registers[operands[0].reg] = registers[operands[0].reg] + registers[operands[1].reg]

            print(f"\nAdd completed, EAX: {registers[X86_REG_EAX]}")
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break
    #Subtract command
    elif mnemonic == "sub":
        #Add values in two registers
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            registers[operands[0].reg] = registers[operands[0].reg] - registers[operands[1].reg]

            print(f"\nSubtract completed, EAX: {registers[X86_REG_EAX]}")
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break
    #Signed multiply command
    elif mnemonic == "imul":
        #Add values in two registers
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            registers[operands[0].reg] = registers[operands[0].reg] * registers[operands[1].reg]

            print(f"\nSigned multiply completed, EAX: {registers[X86_REG_EAX]}")
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break
    #Unsigned multiply command
    elif mnemonic == "mul":
        #Add values in two registers
        if operands[0].type == X86_OP_REG:
            registers[X86_REG_EAX] = abs(registers[X86_REG_EAX] * registers[operands[0].reg])

            print(f"\nUnsigned multiply completed, EAX: {registers[X86_REG_EAX]}")
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break
    #Signed division command
    elif mnemonic == "idiv":
        #Add values in two registers
        if operands[0].type == X86_OP_REG:
            registers[X86_REG_EDX] = registers[X86_REG_EAX] % registers[operands[0].reg]
            registers[X86_REG_EAX] = registers[X86_REG_EAX] // registers[operands[0].reg]

            print(f"\nSigned division completed, EAX: {registers[X86_REG_EAX]}")
            print(f"\nSigned division completed, EDX: {registers[X86_REG_EDX]}")
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break
    #Unsigned division command
    elif mnemonic == "div":
        #Add values in two registers
        if operands[0].type == X86_OP_REG:
            registers[X86_REG_EDX] = abs(registers[X86_REG_EAX] % registers[operands[0].reg])
            registers[X86_REG_EAX] = abs(registers[X86_REG_EAX] // registers[operands[0].reg])

            print(f"\nUnsigned division completed, EAX: {registers[X86_REG_EAX]}")
            print(f"\nUnsigned division completed, EDX: {registers[X86_REG_EDX]}")
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break
    #Unimplemented instructions
    else:
        print(f"\nInstruction not implemented: {instruction.mnemonic}")
        break

    #Increment EIP to next instruction location based on size of last executed instruction
    registers[X86_REG_EIP] += instruction.size