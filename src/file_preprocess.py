'''
Author: 'Taurus052' 'qq_52550864@gitcode.net'
Date: 2023-06-30 15:47:15
LastEditTime: 2023-07-07 14:58:36
'''
import re
import sys

input_file = sys.argv[1]
output_file = sys.argv[2]

function_pattern = r"\s*([\da-f]+)\s*<(.+)>:"
instruction_pattern = r'^\s*([\da-f]+):\s+([\da-f]+)\s+([^:]+)\s+(.+)'

def main(input_file):
    type = judge_type(input_file)
    if type == 1:
        instructions = extract_disassembly_instructions(input_file)
    rewrite_objdump_file(output_file, instructions)
    
def judge_type(input_file_path):
    type = None
    with open(input_file_path, 'r') as file:
        lines = file.readlines()
        for line in lines[:15]:
            if '#' in line:
                type = 1
    return type

def extract_disassembly_instructions(input_file_path):
    instructions = []
    with open(input_file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            instr_match = re.search(instruction_pattern, line)
            func_match = re.search(function_pattern, line)
            if func_match:
                if instructions == []:
                    instructions.append(line)
                else:
                    instructions.append('\n' + line)
            elif instr_match:
                instructions.append(line)
    return instructions

def rewrite_objdump_file(output_file, instructions):
    with open(output_file, 'w') as file:
        for instruction in instructions:
            file.write(instruction)

main(input_file)

