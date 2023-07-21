# CFIEE：A Critical Metadata Extraction Engine for RISC-V Runtime CFI


#### Author: @Taurus052

### Program dependencies

 - riscv64-unknown-elf toolchain (If you need to disassemble .elf file)
 - Python modules:
	 - os
	 - re
	 - sys
	 - hashlib
	 - tkinter
	 - threading
	 - subprocess
	 - matplotlib
	 - networkx
	 - graphviz

### Program Function
&nbsp; &nbsp;&nbsp; &nbsp;This program is used to analyze RISC-V ELF file and extract control flow information.

### Program Input
&nbsp; &nbsp;&nbsp; &nbsp;The program requires an RISC-V executable file(.elf) as input, which can be generated using the RISC-V toolchain.

### Program Output
All files will be stored in **"output_files"** directory.
#### 1.  'xxx_basic_block.txt': 
&nbsp; &nbsp;&nbsp; &nbsp; This file contains all Basic block information obtained by Program analysis. The number of each Basic block, the start and end addresses (and instructions), the length of the Basic block, the jump target address (and instructions) of the Basic block, and the instructions in the Basic block are all reflected in the file.
#### 2. 'xxx_forward_transfers.txt':
&nbsp; &nbsp;&nbsp; &nbsp; This file contains all control transfer instructions and their target instructions within the analyzed functions. 
#### 3. 'xxx_bin/hex_basic_block_inf.txt':
&nbsp; &nbsp;&nbsp; &nbsp;This file contains the PC address and instructions of binary /hexadecimal instructions in the Basic block, as well as the hash value calculated based on binary /hexadecimal instructions.
#### 4. 'xxx_function_addr.txt':
&nbsp; &nbsp;&nbsp; &nbsp; This file contains the function's start&end addresses.
#### 5. 'xxx_control_transfer.bin':
&nbsp; &nbsp;&nbsp; &nbsp; This binary file contains all control transfer instructions' addresses and their target addresses. The first 16 bits of each line is the binary address of the control transfer instruction, and the last 16 bits are the address of the transfer target. 
#### 6.'xxx_forward_transfers_per_function.png':
&nbsp; &nbsp;&nbsp; &nbsp; This is a figure that shows the number of forward control transfer instructions (including unconditional direct jumps and branches) in different function.
#### 7. ‘xxx_function_call_relationship.png':
&nbsp; &nbsp;&nbsp; &nbsp; This picture shows the function call relationship of the current program. If there is a letter "j" after the function name in the figure, it means that the function is not called by the "jal" instruction, but jumps from the "j" instruction at the end of the previous function
#### 8. 'xxx_CFG.svg':
&nbsp; &nbsp;&nbsp; &nbsp; This is a control flow graph of the entire program flow in svg format.


### Program Usage
&nbsp; &nbsp;&nbsp; &nbsp;This program can be used via the command line, with the following usage:

	python CFIEE.py
	
&nbsp; &nbsp;&nbsp; &nbsp; In the interface of CFIEE, we have marked the usage steps for you, and you only need to follow the steps to perform corresponding operations. It should be noted that we do not force you to use the disassembly function here, you can complete the disassembly of your executable file in advance and start directly from STEP2. CFIEE invokes the riscv64-unknown-elf-objdump toolchain on your computer.

### Notice

 1. All development and testing processes for this program are based on the T-Head Xuantie E906 RISC-V processor using the RV32IMAF( C ) instruction set. The selected RISC-V toolchain is Xuantie-900-gcc-elf-newlib-x86_64-V2.6.1. Its disassembly toolchain is GNU objdump (GNU Binutils) 2.35.
We **cannot** guarantee the correctness of this program when analyzing the disassembly files of other RISC-V instruction sets.
 3. Current program **cannot** analyze information related to indirect jumps. The target addresses of all indirect jump instructions are set to "FFFF". 
