# CFIEE： A Control Flow Information Extraction Engine for RISC-V


#### Author: @Taurus052

### Program Function
&nbsp; &nbsp;&nbsp; &nbsp;This program is used to analyze RISC-V ELF file and extract CFG related information (excluding the control flow graph in the form of picture).

### Program Input
&nbsp; &nbsp;&nbsp; &nbsp;The program requires an ELF disassemble file(.txt) as input, which can be generated using the RISC-V toolchain.

### Program Output
All files will be stored in "output_files" directory.
#### 1.  'basic_block.txt': 
&nbsp; &nbsp;&nbsp; &nbsp; This file contains all Basic block information obtained by Program analysis. The number of each Basic block, the start and end addresses (and instructions), the length of the Basic block, the jump target address (and instructions) of the Basic block, and the instructions in the Basic block are all reflected in the file.
#### 2. 'may_used_control_transfers.txt':
&nbsp; &nbsp;&nbsp; &nbsp; This file contains all control transfer instructions and their target instructions within the analyzed functions. 
#### 3. 'bin/hex_basic_block_inf.txt':
&nbsp; &nbsp;&nbsp; &nbsp;This file contains the PC address and instructions of binary /hexadecimal instructions in the Basic block, as well as the hash value calculated based on binary /hexadecimal instructions.
#### 4. 'function_information.txt':
&nbsp; &nbsp;&nbsp; &nbsp; This file contains the function's start&end addresses.
### Program Usage
&nbsp; &nbsp;&nbsp; &nbsp;This program can be used via the command line, with the following usage:

	python Analyze.py
	
&nbsp; &nbsp;&nbsp; &nbsp; In the pop-up window, you can click the **"Browse"** button to select the disassembled .txt file. Then click the **"Preprocess file"** button. After the preprocessing, please select the hash algorithm and the length of the hash value according to your needs. The length of the hash value can be selected in the menu, or you can enter a custom value (it needs to be within the range of the result length supported by the hash function). At last, you can click the **"Analyze"** button to  startup analysis.


### Notice

 1. All development and testing processes for this program are based on the T-Head Xuantie E906 RISC-V processor using the RV32IMAF instruction set. The selected RISC-V toolchain is Xuantie-900-gcc-elf-newlib-x86_64-V2.6.1. Its disassembly toolchain is GNU objdump (GNU Binutils) 2.35.
We **cannot** guarantee the correctness of this program when analyzing the disassembly files of other RISC-V instruction sets.
 3. Current program **cannot** analyze information related to indirect jumps. The target addresses of all indirect jump instructions are set to "FFFF". 
