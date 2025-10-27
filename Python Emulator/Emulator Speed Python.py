from capstone import *
from capstone.x86 import *

import time

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

#EIP is instruction pointer
#Set it to beginning of code
registers[X86_REG_EIP] = 0

#Start operation time
start_time = time.perf_counter()

#While instruction pointer has not reached end of code yet
while registers[X86_REG_EIP] != len(code):
    address = registers[X86_REG_EIP] #Variable to hold current instruction pointer

    #Take next instructions for length of up to maximum length of 16 bits
    instruction = next(cs.disasm(code[address:address+15], address))
    mnemonic = instruction.mnemonic
    operands = instruction.operands

    #Move command
    if mnemonic == "mov":
        #Move immediate value to register
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            registers[operands[0].reg] = operands[1].value.imm
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break
    #Add command
    elif mnemonic == "add":
        #Add values in two registers
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            registers[operands[0].reg] = registers[operands[0].reg] + registers[operands[1].reg]
        else:
            print(f"\n{instruction.mnemonic} variation not implemented")
            break

    #Increment EIP to next instruction location based on size of last executed instruction
    registers[X86_REG_EIP] += instruction.size   

#End operation time
end_time = time.perf_counter()

#Calculate runtime
elapsed_time = end_time - start_time

print(f"Elapsed time: {elapsed_time:.10f} seconds")