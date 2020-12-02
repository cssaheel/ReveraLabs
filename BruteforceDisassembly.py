# This script attempts to force the disassembly of non-disassembled code bytes.
# it happens that Ghidra sometimes miss-identify some code bytes as data bytes,
# in my experience this frequently happens when disassembling non-x86/x64 programs. This leads to a 
# non-fully disassembled program, and it can be can be hard to identify those missed (non-disassembled)
# code bytes manually. To address this issue Ghidra offers Aggressive Instruction Finder analysis, however,
# it is not always helpful with different architectures (Motorola, MIPS, .. etc).
# Ideally, you want to disassemble missed functions, so it is advisable to focus on
# functions leading bytes (those bytes you find in the function prologue), for example in x86 arch you
# should be looking for "push ebp"=0x55 followed by "mov ebp, esp"=0x8bec, thus, the bytes you are looking
# for are 558bec, the script will take these bytes as an input, and it will search the entire program
# looking for them. The script also take the first instruction name as an input, such that
# after finding those bytes, it attempts to disassemble the found bytes location and see if the
# first disassembled instruction matches with the instruction name you provided, if it does, then Ghidra is
# tasked to disassemble the location.

#@author Abdulelah Alsaheel - Twitter: @0xAlsaheel 

import string
from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.util import PseudoDisassembler


max_payload_mbytes = 999 # how much memory you are willing to reserve
matchLimit = 99999 # how many instances you would want to check?

instr_bytes = askString("Instruction(s) Bytes", "Enter the instruction(s) bytes you would like to find: ", "5589e5").lower()
instr_name = askString("Instruction Name", "Enter the name of the first instruction you are looking for after resolving those bytes: ", "push").lower()

# quit if we did not get even number of hex values
is_hex = all(c in string.hexdigits for c in instr_bytes)
is_even = len(instr_bytes) % 2 == 0
if not is_hex or not is_even:
	print "Error: Please only enter hex values."
	exit()

instr_bytes = "".join(["\\x" + instr_bytes[i:i+2] for i in range(0, len(instr_bytes), 2)])

decompInterface = DecompInterface()
decompInterface.openProgram(currentProgram)

# ghidra options
newOptions = DecompileOptions() # Current decompiler options
newOptions.setMaxPayloadMBytes(max_payload_mbytes)
decompInterface.setOptions(newOptions)
listing = currentProgram.getListing()
fpapi = FlatProgramAPI(currentProgram)
address_factory = fpapi.getAddressFactory()
psedu_disassembler = PseudoDisassembler(currentProgram)

# search for the specified bytes
minAddress = currentProgram.getMinAddress()
instr_addresses = fpapi.findBytes(minAddress, instr_bytes, matchLimit)

fixed = 0
for target_address in instr_addresses:
	# check if ghidra got this one right
	disassembled_instr = fpapi.getInstructionAt(target_address)
	if not disassembled_instr == None:
		continue

	print "found the bytes at: " + str(target_address)
	disassembled_instr = str(psedu_disassembler.disassemble(target_address))
	# check if it can be disassembled
	if not disassembled_instr == None:
		print "disassembled_instr: " + str(disassembled_instr)
		# check if the instruction name exist in the disassembled instruction
		if instr_name in disassembled_instr:
			 # Start disassembling at the specified address.
			fpapi.disassemble(target_address)
			fixed += 1

print "\nBrute-force disassembly: Fixed " + str(fixed) + " code locations\n"
