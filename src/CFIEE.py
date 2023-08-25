'''
Author: Taurus052
Date: 2023-07-14 15:34:43
LastEditTime: 2023-08-25 15:11:41
'''

import os
import hashlib
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import threading
import subprocess
import matplotlib.pyplot as plt
import graphviz


# branch instructions
branch_inst = ["beq", "bne", "blt", "bltu", "bge", "bgeu", "beqz", "bnez", "bltz", "blez", "bgtz", "bgez", "bgt", "bgtu", "ble", "bleu"]
# jump instruction
unconditional_jump_inst = ["jal", "j"]
indirect_jump_inst = ["jr", "jalr"]

current_dir = os.path.dirname(os.path.abspath(__file__))
#Change the current working directory to the directory of the script
os.chdir(current_dir)

def main(objdump_file, Hash_algorithm, Hash_value_length, program_name):
    output_directory = os.path.join(os.path.dirname(os.getcwd()), 'output_files')
    
    function_line_ranges, function_addr_ranges, function_instr =  get_func_information(objdump_file)
    
    ### find the function to visit 
    function_call_instr = {}
    # extra_func_name = extract_function_before_xx(objdump_file, '<__to_main>')
    to_visit_functions, visited_functions_id, visited_functions, function_call_instr  \
                            = find_to_visit_function(objdump_file, function_instr,function_addr_ranges,\
                                '<__start>',function_call_instr, visited_functions = None,visited_functions_id=None)
        
    all_instr, all_control_transfer_instr_addr, sorted_functions_with_jump_instr_addr = \
        get_all_control_transfer_instr(objdump_file, function_addr_ranges,visited_functions)

    ret_instr_addr, function_have_ret_instr =  find_ret_instruction(visited_functions, function_addr_ranges, function_instr)
    
    function_call_relationship = get_function_call_relationship(function_call_instr, function_addr_ranges, output_directory, program_name)
    
    return_target = get_return_relationship(function_call_relationship, ret_instr_addr, function_call_instr, \
                                                all_instr, function_addr_ranges)
        
    used_function_instr = extract_used_function_instr(function_instr, visited_functions)
    
    address, machine_code, mnemonic, operands = get_func_machine_code(used_function_instr)
    
    end_addr_list, branch_or_jump_target_addr, \
        branch_taken_start_addr, all_taken_target_addr, order_start_addr_list= \
            get_the_addr_information_for_basic_block(address, mnemonic, operands, function_addr_ranges)
    
    
    basic_block = create_basic_blocks_in_order(order_start_addr_list, end_addr_list, used_function_instr, function_addr_ranges,\
                                                ret_instr_addr,return_target)
                                       
    basic_block =  create_basic_blocks_start_with_taken_target(all_taken_target_addr, basic_block, order_start_addr_list, used_function_instr)
    
    sorted_basic_blocks =  sort_basic_blocks(basic_block)
    

    export_results(function_addr_ranges, program_name + '_function_addr.txt',
                all_instr, sorted_functions_with_jump_instr_addr, program_name + '_forward_transfers.txt', \
                    program_name + '_control_transfer.bin',\
                program_name + '_basic_block.txt', sorted_basic_blocks,
                program_name + '_bin_basic_block_inf.txt', program_name + '_hex_basic_block_inf.txt',
                Hash_algorithm, Hash_value_length, output_directory, program_name)
    
    generate_CFG(basic_block, program_name, output_directory)
    
    # generate_main_CFG(basic_block, program_name, output_directory, function_addr_ranges)



def get_func_machine_code(input_data):
    '''
    Extracts machine code information from the input data.

    Args:
        input_data (list): Used function instructions.

    Returns:
        tuple: A tuple containing lists of addresses, machine codes, mnemonics, and operands.

    '''
    # Initialize lists to store the machine code information
    address = []
    machine_code = []
    mnemonic = []
    operands = []

    # Iterate over the input data
    for line in input_data:
        if len(line) == 1:
            break

        # Split the line into tokens
        tokens = line.split()

        # Extract the address, machine code, mnemonic, and operands
        if len(tokens) == 3:    
            address.append(tokens[0][:-1])  
            machine_code.append(tokens[1])
            mnemonic.append(tokens[2])
            operands.append('')
        else:
            address.append(tokens[0][:-1])  
            machine_code.append(tokens[1])
            mnemonic.append(tokens[2])
            operands.append(tokens[3])

    # Return the extracted machine code information as a tuple of lists
    return address, machine_code, mnemonic, operands

def get_func_information(objdump_file):
    '''
    Extract function information from the objdump file.

    Args:
        objdump_file (str): Path to the objdump file.

    Returns:
        tuple: A tuple containing dictionaries of function line ranges, function address ranges,
               and function instructions.

    '''
    # Read the objdump file
    with open(objdump_file, 'r') as f:
        lines = f.readlines()
    # Initialize variables
    function_line_ranges = {}
    function_addr_ranges = {}
    function_instr = {}
    start_line = 0
    in_function = False
    function_name = ""
    # Process each line in the file
    for i, line in enumerate(lines):
        # Check if the line indicates the start of a function
        if line.endswith(">:\n"): 
            in_function = True
            function_name = line.split()[-1][:-1]  # Extract the function name
            start_line = i + 1
            func_instr = [] # Initialize a list to store the function instructions
        # Check if the line indicates the end of a function
        elif line.startswith("\n") or "..." in line: 
            if in_function:
                in_function = False
                end_line = i - 1
                # Get the start and end addresses based on line numbers
                start_address = lines[start_line].split()[0][:-1]
                end_address = lines[end_line].split()[0][:-1]
                 # Store the function information in the dictionaries
                function_line_ranges[function_name] = (start_line, end_line)
                function_addr_ranges[function_name] = (start_address, end_address)
                function_instr[function_name] = func_instr
        # Check if the line is an instruction within a function
        else:
            if in_function:
                instr = line.strip()
                func_instr.append(instr)
       
    return function_line_ranges, function_addr_ranges, function_instr

def write_functions_information(function_addr_ranges, output_file, output_directory):
    func_info_path = os.path.join(output_directory, output_file)
    with open(func_info_path, 'w') as f:
        for func_name, func_range in function_addr_ranges.items():
            f.write(func_name + ':' + '\n' + '\tstart_addr:' + ' ' + str(func_range[0]) \
                +'\n' + '\tend_addr:' + ' ' + str(func_range[1]) + '\n')

          
def find_to_visit_function(objdump_file, function_instr, function_addr_ranges, func_name, function_call_instr,\
                            visited_functions = None, visited_functions_id=None ):
    '''
    Find functions to visit based on the function's instructions and addresses.

    Args:
        objdump_file (str): Path to the objdump file.
        function_instr (dict): Dictionary containing the instructions of each function.
        function_addr_ranges (dict): Dictionary containing the address ranges of each function.
        func_name (str): Name of the current function.
        function_call_instr (dict): Dictionary to store the call instructions for each function.
        visited_functions (set, optional): Set of visited functions. Defaults to None.
        visited_functions_id (bool, optional): Identifier for whether visited_functions has been initialized. Defaults to None.

    Returns:
        tuple: A tuple containing the set of functions to visit, the visited_functions_id flag,
                the visited functions, and the function_call_instr dictionary.

    '''
    
    # Initialize visited_functions set if not already initialized
    if visited_functions_id is None:
        visited_functions = set()
        visited_functions_id = True
    # Read objdump file
    with open(objdump_file, 'r') as file:
        lines = file.readlines()

    func_addr_range = function_addr_ranges[func_name]    
    call_instrs = []
    
    # Search for called functions in the function range
    to_visit_functions = set()
    for line in function_instr[func_name]:
        if len(function_instr[func_name]) == 1:
            if line.split()[2] == 'jal' or line.split()[2] ==  'j' :
                    operand = line.split()[3]
                    if ',' in operand:
                        jump_target = operand.split(',')[1]
                        if int(jump_target,16) > int(func_addr_range[1],16) or int(jump_target,16) < int(func_addr_range[0],16):
                            call_instrs.append(line)
                    elif ',' not in operand:
                        jump_target = operand
                        if int(jump_target,16) > int(func_addr_range[1],16) or int(jump_target,16) < int(func_addr_range[0],16):
                            call_instrs.append(line)
                    
                    for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                        if int(jump_target,16) >= int(func_addr_range[0],16) and int(jump_target,16) <= int(func_addr_range[1],16):
                            to_visit_functions.add(to_visit_func_name)
                            called_func_name = func_name
                            break
            
            # branch instr    
            elif  any(all(instr_char in line.split()[2] for instr_char in instr) for instr in branch_inst):
                operand = line.split()[3]
                jump_target = operand.split(',')[-1]
                
                if line == function_instr[func_name][-1]:# Check if the last instruction is a branch instruction
                    for b_next_func_name in function_addr_ranges.keys():
                        if b_next_func_name != func_name:
                            to_visit_functions.add(b_next_func_name)
                            called_func_name = func_name
                            break
                for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                    if int(jump_target,16) >= int(func_addr_range[0],16) and int(jump_target,16) <= int(func_addr_range[1],16):
                        to_visit_functions.add(to_visit_func_name)
                        called_func_name = func_name
                        break

        else:
            if line.split()[2] == 'jal' or line.split()[2] ==  'j' :
                operand = line.split()[3]
                if ',' in operand:
                    jump_target = operand.split(',')[-1]
                    if int(jump_target,16) > int(func_addr_range[1],16) or int(jump_target,16) < int(func_addr_range[0],16):
                        call_instrs.append(line)
                elif ',' not in operand:
                    jump_target = operand
                    if int(jump_target,16) > int(func_addr_range[1],16) or int(jump_target,16) < int(func_addr_range[0],16):
                        call_instrs.append(line)

                for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                    if int(jump_target,16) >= int(func_addr_range[0],16) and int(jump_target,16) <= int(func_addr_range[1],16):
                        to_visit_functions.add(to_visit_func_name)
                        called_func_name = func_name
                        break
            # branch instr
            elif  any(all(instr_char in line.split()[2] for instr_char in instr) for instr in branch_inst):
                operand = line.split()[3]
                jump_target = operand.split(',')[-1]
                
                if line == function_instr[func_name][-1]:# # Check if the last instruction is a branch instruction
                    for b_next_func_name in function_addr_ranges.keys():
                        if b_next_func_name != func_name:
                            to_visit_functions.add(b_next_func_name)
                            called_func_name = func_name
                            break
                for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                    if int(jump_target,16) >= int(func_addr_range[0],16) and int(jump_target,16) <= int(func_addr_range[1],16):
                        to_visit_functions.add(to_visit_func_name)
                        called_func_name = func_name
                        break

    function_call_instr[func_name] = call_instrs
    # If no called functions found, add the next sequential function as to visit
    if not to_visit_functions:
        found = False
        for next_func_name in function_addr_ranges.keys():
            if found:
                to_visit_functions.add(next_func_name)
                called_func_name = func_name
                break
            if next_func_name == func_name:
                found = True
    
    # Recursively search for called functions in the called functions
    for been_called_func_name in to_visit_functions:
        if been_called_func_name not in visited_functions:
            visited_functions.add(called_func_name)
            visited_functions.add(been_called_func_name)
            find_to_visit_function(objdump_file, function_instr, function_addr_ranges, been_called_func_name, \
                                    function_call_instr,visited_functions, visited_functions_id)
    

    visited_functions = sorted(visited_functions, key=lambda func_name: int(function_addr_ranges[func_name][0], 16))

    
    return to_visit_functions, visited_functions_id, visited_functions, function_call_instr    


def find_ret_instruction(visited_functions, function_addr_ranges, function_instr):
    '''
    Find return instructions within visited functions.

    Args:
        visited_functions (list): List of visited function names.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.
        function_instr (dict): Dictionary mapping function names to their instructions.

    Returns:
        tuple: A tuple containing a dictionary of return instruction addresses and a list of functions
               that have return instructions.

    '''
    
    # Initialize variables
    ret_instr_addr = {}
    function_have_ret_instr = []

    # Process each visited function
    for func_name in visited_functions:
        start_addr, end_addr = function_addr_ranges[func_name]
        instrs = function_instr[func_name]

        # Search for return instructions within the function's address range
        for line in instrs:
            tokens = line.split()
            instr_addr = tokens[0][:-1]
            mnemonic = tokens[2]

            # Check if the instruction is a return instruction
            if int(instr_addr, 16) >= int(start_addr, 16) and int(instr_addr, 16) <= int(end_addr, 16) \
                    and mnemonic == 'ret':
                # Store the return instruction address in the dictionary
                if func_name in ret_instr_addr:
                    ret_instr_addr[func_name].append(instr_addr)
                else:
                    ret_instr_addr[func_name] = [instr_addr]
                # Add the function to the list of functions with return instructions
                function_have_ret_instr.append(func_name)

    # Return the dictionary of return instruction addresses and the list of functions with return instructions
    return ret_instr_addr, function_have_ret_instr

def get_function_call_relationship(function_call_instr, function_addr_ranges, output_directory, program_name):
    '''
    Get the function call relationship between functions.

    Args:
        function_call_instr (dict): Dictionary mapping function names to their function call instructions.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.

    Returns:
        dict: Dictionary representing the function call relationships.

    '''
    
    # Initialize dictionary to store the function call relationship
    function_call_relationship = {}
    
    # Iterate over the function call instructions
    for caller_func_name, call_instrs in function_call_instr.items():
        for call_instr in call_instrs:
            tokens = call_instr.split()
            instr_addr = tokens[0][:-1]
            mnemonic = tokens[2]
            operand = tokens[3]
            if ',' in operand:
                jump_target = operand.split(',')[-1]
            else:
                jump_target = operand
            
            # Iterate over the function address ranges
            for callee_func_name, address in function_addr_ranges.items():
                func_start_addr = address[0]
                func_end_addr = address[1]
                
                 # Check if the jump target matches the start address of the callee function
                if mnemonic == 'jal':
                    if jump_target in func_start_addr:
                        if caller_func_name in function_call_relationship:
                            function_call_relationship[caller_func_name].append(callee_func_name)
                        else:
                            function_call_relationship[caller_func_name] = [callee_func_name]
                        break
                elif mnemonic == 'j':
                    if jump_target in func_start_addr:
                        if caller_func_name in function_call_relationship:
                            function_call_relationship[caller_func_name].append(callee_func_name)
                        else:
                            function_call_relationship[caller_func_name] = [callee_func_name + ' *']
                        break 

    # Remove duplicates from the function call relationship
    for caller_func_name in function_call_relationship:
        function_call_relationship[caller_func_name] = list(set(function_call_relationship[caller_func_name]))
    # Sort the function call relationship based on the start address of the caller functions
    function_call_relationship = {k: v for k, v in sorted(function_call_relationship.items(), key=lambda item: int(function_addr_ranges[item[0]][0], 16))}
    
    G = graphviz.Digraph(format='svg')

    # Add nodes and edges to the graph
    for caller_func_name, callee_func_names in function_call_relationship.items():
        G.node(caller_func_name)
        for callee_func_name in callee_func_names:
            G.node(callee_func_name)
            G.edge(caller_func_name, callee_func_name)

    # Set the output file path
    output_file = os.path.join(output_directory, f'{program_name}_function_call_relationship')

    # Render the graph and save it to a file
    G.render(filename=output_file, cleanup=True, view=False)
 
    return function_call_relationship

def get_return_relationship(function_call_relationship, ret_instr_addr, function_call_instr, all_instr,function_addr_ranges):
    '''
    Get the return relationship between functions and the corresponding return targets.

    Args:
        function_call_relationship (dict): Dictionary representing the function call relationships.
        ret_instr_addr (dict): Dictionary mapping function names to their return instruction addresses.
        function_call_instr (dict): Dictionary mapping function names to their function call instructions.
        all_instr (list): List of all instructions.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.

    Returns:
        dict: Dictionary representing the return targets for each function.

    '''
    
    # Initialize dictionaries to store the return relationship and return targets
    return_relationship = {}
    return_target = {}
    
    # Iterate over the function call relationship
    for caller_func_name, callee_func_names in function_call_relationship.items():
        for func_name in callee_func_names:
            try:
                callee_func_name = func_name.split()[0]
                 # The function where the ret instruction is located is the jump target function of the j instruction
                if len(func_name.split()) != 1 and func_name.split()[1] == '*':
                    last_func = [key for key, names in function_call_relationship.items() if caller_func_name.strip('<>').strip() in [name.strip('<>').strip() for name in names]]
                    last_func_str =  ' '.join(last_func)
                    if callee_func_name in ret_instr_addr.keys():
                        if callee_func_name in return_relationship:
                            return_relationship[callee_func_name].append(last_func_str + ' ' + caller_func_name)
                        else:
                            return_relationship[callee_func_name] = [last_func_str + ' ' + caller_func_name]
                    
                else:
                    if callee_func_name in ret_instr_addr.keys():
                        if callee_func_name in return_relationship:
                            return_relationship[callee_func_name].append(caller_func_name)
                        else:
                            return_relationship[callee_func_name] = [caller_func_name]

            except KeyError:
                print(f"KeyError: {callee_func_name} not found in ret_instr_addr")
    
    # Iterate over the return relationship to find return targets
    for ret_key, ret_funcs in return_relationship.items():
        for func in ret_funcs:
            func_n = func.split()[0]
            if func in function_call_instr.keys() and ' ' not in func:
                for jal_instr in function_call_instr[func_n]:
                    tokens = jal_instr.split()
                    instr_addr = tokens[0][:-1]
                    instr_target_func = tokens[-1]
                    if instr_target_func == ret_key:
                        for i in range(len(all_instr)):
                            if int(all_instr[i].split()[0][:-1],16) == int(instr_addr,16):
                                for func_name, addr in function_addr_ranges.items():
                                    if int(all_instr[i+1].split()[0][:-1],16) >= int(addr[0],16) and \
                                        int(all_instr[i+1].split()[0][:-1],16) <= int(addr[1],16):
                                        if ret_key in return_target:
                                            return_target[ret_key].append(func_name + ' '+all_instr[i+1].split()[0][:-1])
                                        else:
                                            return_target[ret_key] = [func_name + ' '+all_instr[i+1].split()[0][:-1]]
                                        break
                                    else:
                                        continue
                    else:
                        continue
            elif func_n in function_call_instr.keys() and ' ' in func:
                func_n2 = func.split()[-1]
                for jal_instr in function_call_instr[func_n]:
                    tokens = jal_instr.split()
                    instr_addr = tokens[0][:-1]
                    instr_target_func = tokens[-1]
                    if instr_target_func == func_n2:
                        for i in range(len(all_instr)):
                            if int(all_instr[i].split()[0][:-1],16) == int(instr_addr,16):
                                for func_name, addr in function_addr_ranges.items():
                                    if int(all_instr[i+1].split()[0][:-1],16) >= int(addr[0],16) and \
                                        int(all_instr[i+1].split()[0][:-1],16) <= int(addr[1],16):
                                        if ret_key in return_target:
                                            return_target[ret_key].append(func_name + ' '+all_instr[i+1].split()[0][:-1])
                                        else:
                                            return_target[ret_key] = [func_name + ' '+all_instr[i+1].split()[0][:-1]]
                                        break
                                    else:
                                        continue
                    else:
                        continue
    
    return return_target


def get_all_control_transfer_instr(objdump_file, function_addr_ranges,visited_functions):
    '''
    Get all control transfer instructions within the given objdump file.

    Args:
        objdump_file (str): Path to the objdump file.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.
        visited_functions (list): List of visited function names.

    Returns:
        tuple: A tuple containing the list of all instructions, a list of all control transfer instruction addresses,
               and a dictionary mapping visited function names to their control transfer instruction addresses.

    '''
    # Initialize lists and dictionaries
    all_instr = []
    address = []
    machine_code = []
    mnemonic = []
    operands = []
    all_control_transfer_instr_addr = []   
    
    # Read the objdump file and extract instructions
    with open(objdump_file,'r') as file:
        for line in file:
            if line.startswith(" "):
                all_instr.append(line.strip())
    
    # Process each instruction and extract relevant information            
    for i in range(len(all_instr)):
        tokens = all_instr[i].split()
        if len(tokens) == 3:    
            address.append(tokens[0][:-1])  
            machine_code.append(tokens[1])
            mnemonic.append(tokens[2])
            operands.append('')
        else:
            address.append(tokens[0][:-1])  
            machine_code.append(tokens[1])
            mnemonic.append(tokens[2])
            operands.append(tokens[3])
    
    # Find all control transfer instruction addresses
    for i in range(len(mnemonic)):
        if mnemonic[i] in branch_inst:
            operand = operands[i].split(',')
            all_control_transfer_instr_addr.append(address[i] + ',' + operand[-1])
            
        elif mnemonic[i] == 'jal':
            operand = operands[i].split(',')
            all_control_transfer_instr_addr.append(address[i] + ',' + operand[-1]) 
            
        elif mnemonic[i] == 'j':
            if ',' in operands[i]:
                operand = operands[i].split(',')
                all_control_transfer_instr_addr.append(address[i] + ',' + operand[-1])
            elif ',' not in  operands[i]:
                operand = operands[i].split() 
                all_control_transfer_instr_addr.append(address[i] + ',' + operand[-1])            
    
    # Create a dictionary to store control transfer instruction addresses for each visited function
    functions_with_jump_instr_addr = {func_name: [] for func_name in visited_functions}
    
    # Assign control transfer instruction addresses to their corresponding functions
    for i in range(len(all_control_transfer_instr_addr)):
        for func_name in visited_functions:
            func_addr_range = function_addr_ranges[func_name]
            if int(all_control_transfer_instr_addr[i].split(',')[0],16) >= int(func_addr_range[0],16) and \
                int(all_control_transfer_instr_addr[i].split(',')[0],16) <= int(func_addr_range[1],16):
                functions_with_jump_instr_addr[func_name].append(all_control_transfer_instr_addr[i])
                break
    
    # Sort the dictionary based on the starting address of each function
    sorted_functions_with_jump_instr_addr = {k: v for k, v in sorted(functions_with_jump_instr_addr.items(), \
                                                key=lambda item: int(function_addr_ranges[item[0]][0], 16))}
   
    return all_instr, all_control_transfer_instr_addr, sorted_functions_with_jump_instr_addr

def write_in_may_used_control_transfer_instr(all_instr, functions_with_jump_instr_addr, output_file1, output_file2 ,\
                                                output_directory, program_name):
    ct_path = os.path.join(output_directory, output_file1)
    bin_path = os.path.join(output_directory, output_file2)
    
    with open (ct_path,'w',encoding='utf-8') as file1, open(bin_path,'wb') as file2:
        for func_name in functions_with_jump_instr_addr:
            file1.write('\n' + func_name + ':\n'+'\n')
            
            for line in functions_with_jump_instr_addr[func_name]:
                addr, taken_target = line.split(',')
                target_line_num = None
                
                int_addr = int(addr, 16)
                int_target = int(taken_target, 16)
                bin_addr = bin(int_addr)[2:].zfill(16)
                bin_target = bin(int_target)[2:].zfill(16)
                addr_bytes = bin_addr.encode('utf-8')
                target_bytes = bin_target.encode('utf-8')
                file2.write(addr_bytes + target_bytes + b'\n')

                for line_num , instr in enumerate(all_instr):
                    if instr.startswith(taken_target):
                        target_line_num = line_num
                        break
                
                if target_line_num is not None:
                    jump_instr_line_num = None
                    for line_num , instr in enumerate(all_instr):
                        if instr.startswith(addr):
                            jump_instr_line_num = line_num
                            break      
                    if jump_instr_line_num is not None:
                        file1.write('j/b_instr: '+all_instr[jump_instr_line_num] + '\n')
                        file1.write('t_instr:   '+all_instr[target_line_num] + '\n')
                        file1.write('\n')
    
    instruction_count = []
    function_names = []

    for function_name, jump_instructions in functions_with_jump_instr_addr.items():
        instruction_count.append(len(jump_instructions))
        function_names.append(function_name)

    # Set the figure size and spacing
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.subplots_adjust(bottom=0.3)

    # Plot the bar chart
    bars = plt.bar(function_names, instruction_count)
    plt.xlabel('Function Name')
    plt.ylabel('Transfer Instructions')
    plt.title(program_name + ' Transfers per Function (Forward)')

    # Rotate the x-axis labels to prevent overlap
    plt.xticks(rotation=90)

    # Add data labels to the bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, height, str(int(height)), ha='center', va='bottom')

    # Save the figure to a file
    plt.savefig(os.path.join(output_directory, program_name + '_forward_transfers_per_function.svg'))


def extract_used_function_instr(function_instr, visited_functions):
    used_function_instr = []
        
    for func_name, instr_list in function_instr.items():
        if func_name in visited_functions:
            used_function_instr.extend(instr_list)
            
    used_function_instr.sort(key=lambda x: int(x.split(':')[0], 16))
    # with open(output_file,'w',encoding='utf-8') as file :
    #     for instr in used_function_instr:
    #         file.write(instr + '\n')
            
    return used_function_instr

def get_the_addr_information_for_basic_block(address, mnemonic, operands, function_addr_ranges):
    '''
    Get address information for basic block.

    Args:
        address (list): List of instruction addresses.
        mnemonic (list): List of instruction mnemonics.
        operands (list): List of instruction operands.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.

    Returns:
        tuple: A tuple containing the list of end addresses for each function, a list of branch or jump target addresses,
               a list of start addresses for branches that are taken, a list of all taken target addresses,
               and a list of start addresses in order.

    '''
    # Initialize lists and variables
    branch_or_jump_target_addr = []
    order_start_addr_list = []
    end_addr_list = []
    func_end_addr_list = []
    branch_taken_start_addr = []
    branch_i = 0
    all_taken_target_addr = [] # All taken_target address
    
    # Extract function end addresses from function address ranges
    for func, addresses in function_addr_ranges.items():
        func_end_addr = addresses[-1]
        func_end_addr_list.append(func_end_addr)
    
    # Process each instruction and extract address information
    for i in range(len(mnemonic)):
        if i == 0:
            order_start_addr_list.append(address[i])
        
        # function without transfer instruction     
        if address[i] in func_end_addr_list and i+1 <= len(mnemonic):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic):
                order_start_addr_list.append(address[i+1])
                # all_taken_target_addr.append(address[i] + ',' + address[i+1])
            elif i+1 == len(mnemonic):
                continue

        # Deal with branch instructions
        if mnemonic[i] in branch_inst and i+1 < len(mnemonic):
            branch_i += 1
            end_addr_list.append(address[i])
            order_start_addr_list.append(address[i+1])
            branch_or_jump_target_addr.append(address[i+1]+' bnt' + ' ' + str(branch_i))
            operand = operands[i].split(',')
            branch_taken_start_addr.append(operand[-1])
            branch_or_jump_target_addr.append(operand[-1]+' bt' + ' ' + str(branch_i))
            all_taken_target_addr.append(address[i] + ',' + operand[-1])

    # Deal with direct jump instructions
    for i in range(len(mnemonic)):
        if (mnemonic[i] == 'ret'):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic) and mnemonic[i+1]:
                order_start_addr_list.append(address[i+1])
            
        elif (mnemonic[i] == 'jal'):
            end_addr_list.append(address[i])
            operand = operands[i].split(',')
            branch_or_jump_target_addr.append(operand[-1]+' jal')
            all_taken_target_addr.append(address[i] + ',' + operand[-1])
            if i+1 < len(mnemonic):
                order_start_addr_list.append(address[i+1])
                
        elif (mnemonic[i] == 'j'):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic):
                order_start_addr_list.append(address[i+1])

            if ',' in operands[i]:
                operand = operands[i].split(',')
                branch_or_jump_target_addr.append(operand[0]+' j')
                all_taken_target_addr.append(address[i] + ',' + operand[-1])
                
            elif ',' not in  operands[i]:
                operand = operands[i]
                branch_or_jump_target_addr.append(operand+' j')   
                all_taken_target_addr.append(address[i] + ',' + operand)

    # Deal with indirect jump instructions
    for i in range(len(mnemonic)):
        if (mnemonic[i] == 'jalr'):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic):
                order_start_addr_list.append(address[i+1])
            branch_or_jump_target_addr.append('ffff'+' jalr')
            
        elif (mnemonic[i] == 'jr'):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic):    
                order_start_addr_list.append(address[i+1])
            branch_or_jump_target_addr.append('ffff'+' jr')
    
    # Sort the lists
    all_taken_target_addr = sorted(all_taken_target_addr, key=lambda x: int(x.split(',')[0], 16))
    order_start_addr_list = sorted(list(set(order_start_addr_list)),key=lambda x: int(x, 16))
    end_addr_list = sorted(list(set(end_addr_list)),key=lambda x: int(x, 16))
    
    return end_addr_list, branch_or_jump_target_addr, branch_taken_start_addr, \
        all_taken_target_addr, order_start_addr_list

class BasicBlock:
    def __init__(self, name, func, start, end, length, taken_target, not_taken_target, \
        start_instr, end_instr, taken_target_instr, not_taken_target_instr, instr):
        self.name = name
        self.func = func
        self.start = start
        self.end = end
        self.length = length
        self.taken_target = taken_target
        self.not_taken_target = not_taken_target
        self.start_instr = start_instr
        self.end_instr = end_instr
        self.taken_target_instr = taken_target_instr
        self.not_taken_target_instr = not_taken_target_instr
        self.instr = instr    

def calculate_block_length(start_addr, end_addr, used_function_instr):
    start_line = get_line_number(start_addr, used_function_instr)
    end_line = get_line_number(end_addr, used_function_instr)
    block_length = end_line - start_line + 1
    return block_length

def get_line_number(addr, used_function_instr):
    for i, instr in enumerate(used_function_instr):
        if instr.startswith(addr + ":"):
            return i

        
def create_basic_blocks_in_order(order_start_addr_list, end_addr_list, used_function_instr, function_addr_ranges,\
                                ret_instr_addr, return_target):
    '''
    Create basic blocks in order based on the provided address information.

    Args:
        order_start_addr_list (list): List of start addresses for basic blocks in order.
        end_addr_list (list): List of end addresses for basic blocks.
        used_function_instr (list): List of used function instructions.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.
        ret_instr_addr (dict): Dictionary mapping function names to their return instruction addresses.
        return_target (dict): Dictionary mapping function names to their return targets.

    Returns:
        list: List of created basic blocks.

    '''
    # Initialize a list to store the basic blocks
    basic_block = []
    # Create a BasicBlock object for each start address
    for i in range(len(order_start_addr_list)):
        basic_block.append(BasicBlock(0, '', 0, 0, 0, '', '', '', '', '', '', ''))
    
    # Populate the basic block objects with information
    for i in range(len(order_start_addr_list)):
        basic_block[i].name = i
        basic_block[i].start = order_start_addr_list[i]
        basic_block[i].end = end_addr_list[i]
        basic_block[i].length = calculate_block_length(basic_block[i].start, basic_block[i].end, used_function_instr)
        
        # Get the function name for each basic block
        func_name_l = [key for key ,addr in function_addr_ranges.items() if \
                        int(basic_block[i].start,16) >= int(addr[0],16) and int(basic_block[i].start,16) <= int(addr[1],16)]
        func_name = func_name_l[0]
        basic_block[i].func = func_name
        
        # Find the start and end instructions for each basic block 
        block_instr_list = []
        for line in used_function_instr:
            if int(order_start_addr_list[i],16) == int(line[:line.index(':')],16):
                basic_block[i].start_instr = line
            if int(order_start_addr_list[i],16) <= int(line[:line.index(':')],16) <= int(end_addr_list[i],16):
                block_instr_list.append(line)
            if int(end_addr_list[i],16) == int(line[:line.index(':')],16):
                basic_block[i].end_instr = line
                break
        basic_block[i].instr = block_instr_list
        
        # Determine the taken and not-taken targets for each basic block      
        tokens = basic_block[i].end_instr.split()
        if len(tokens) == 3:    
            mnemonic = tokens[2]
            operands = ''
        else:
            mnemonic = tokens[2]
            operands = tokens[3]
        
        if mnemonic in branch_inst:
            operand = operands.split(',')
            basic_block[i].taken_target = operand[-1]
            
        elif mnemonic in unconditional_jump_inst:
            if ',' in operands:
                operand = operands.split(',')
                basic_block[i].taken_target = operand[-1]
            elif ',' not in operands:
                operand = operands.split()
                basic_block[i].taken_target = operand[-1]
       
        # Deal with indirect jump's target
        elif mnemonic in indirect_jump_inst:
            basic_block[i].taken_target = 'register: ' + operands
            # basic_block[i].taken_target = 'FFFF'
            basic_block[i].taken_target_instr = 'FFFFFFFF'

        
        # Deal with 'ret' target
        elif mnemonic == 'ret':
            for func, addresses in ret_instr_addr.items():
                for ret_addr in addresses:
                    if int(basic_block[i].end,16) == int(ret_addr,16):
                        if func in return_target.keys():
                            basic_block[i].taken_target = return_target[func]
                            break
                    else:
                        continue
        
        #branch not taken target            
        if i+1 < len(order_start_addr_list) and mnemonic in branch_inst:
            basic_block[i].not_taken_target = order_start_addr_list[i+1]
    
        # Find the taken target and not taken target instructions
        for line in used_function_instr:
            if basic_block[i].taken_target == line[:line.index(':')]:
                basic_block[i].taken_target_instr = line
            if mnemonic in branch_inst and basic_block[i].not_taken_target == line[:line.index(':')]:
                basic_block[i].not_taken_target_instr = line    
                
    return basic_block    

def create_basic_blocks_start_with_taken_target(all_taken_target_addr, basic_block, order_start_addr_list, used_function_instr):
    '''
    The create_basic_blocks_start_with_taken_target function takes in several parameters including a list of all taken target addresses, \
        a list of existing basic blocks, a list of starting addresses, and a list of used function instructions. 
    The function creates new basic blocks that start with a taken target address and adds them to the existing list of basic blocks. 
    The function returns the updated list of basic blocks.
    '''
    
    # Iterate through all_taken_target_addr to handle new basic block creation
    for addr_pair in all_taken_target_addr:
        jump_addr, target_addr = addr_pair.split(",")
        
        # Check if target address is not already in order_start_addr_list
        if target_addr not in order_start_addr_list:
            # Check if a basic block with the same start address exists
            existing_bb_with_start = next((bb for bb in basic_block if bb.start == target_addr), None)
            
            if existing_bb_with_start:
                in_bb = next((bb for bb in basic_block if int(bb.start,16) <= int(target_addr,16) <= int(bb.end,16)), None)
                # Update the existing basic block's end address
                existing_bb_with_start.end = in_bb.end
                existing_bb_with_start.length = calculate_block_length(existing_bb_with_start.start, existing_bb_with_start.end, used_function_instr)
            else:
                # Find the basic block that contains the target address
                for bb in basic_block:
                    if int(bb.start,16) <= int(target_addr,16) <= int(bb.end,16):
                        # Create a new basic block with the target address as start and bb.end as end
                        new_bb_name = str(len(basic_block)) + ' start_with_taken_target'
                        new_bb_start = target_addr
                        new_bb_end = bb.end
                        new_bb_length = calculate_block_length(new_bb_start, new_bb_end, used_function_instr)
                        new_bb_func = bb.func
                        block_instr_list = []
                        for instr in used_function_instr:
                            if int(new_bb_start,16) == int(instr[:instr.index(':')],16):
                                new_bb_start_instr = instr
                            if int(new_bb_start,16) <= int(instr[:instr.index(':')],16) <= int(new_bb_end,16):
                                block_instr_list.append(instr)
                            if int(new_bb_end,16) == int(instr[:instr.index(':')],16):
                                new_bb_end_instr = instr
                            if int(new_bb_end,16) == int(bb.end,16):
                                new_bb_taken_target = bb.taken_target
                                new_bb_not_taken_target = bb.not_taken_target
                                new_bb_taken_target_instr = bb.taken_target_instr
                                new_bb_not_taken_target_instr = bb.not_taken_target_instr

                        new_bb_instr = block_instr_list
   
                        new_bb = BasicBlock(new_bb_name, new_bb_func, new_bb_start, new_bb_end,\
                            new_bb_length, new_bb_taken_target, new_bb_not_taken_target, new_bb_start_instr, \
                                new_bb_end_instr, new_bb_taken_target_instr, new_bb_not_taken_target_instr, new_bb_instr)
                        basic_block.append(new_bb)
                        break

    return basic_block


def sort_basic_blocks(basic_block):
    sorted_basic_blocks = sorted(basic_block, key=lambda bb: int(bb.start, 16))
    return sorted_basic_blocks

def write_basic_blocks_to_file(file_name, basic_block, output_directory):
    basic_block_path = os.path.join(output_directory, file_name)
    with open(basic_block_path, 'w', encoding='utf-8') as file:
        for bb in basic_block:
            file.write(f'Basic_block Name: {bb.name}\n')
            file.write(f'In Function:      {bb.func}\n')
            file.write(f'Start address:    {bb.start}\n')
            file.write(f'End address:      {bb.end}\n')
            file.write(f'Start instruction: \n\t{bb.start_instr.strip()}\n')
            file.write(f'End instruction: \n\t{bb.end_instr.strip()}\n')
            file.write(f'Length:           {bb.length}\n')
            file.write(f'Taken_Target address:       {bb.taken_target}\n')
            file.write(f'Taken_Target instruction: \n\t{bb.taken_target_instr.strip()}\n')
            file.write(f'Not_Taken_Target address:   {bb.not_taken_target}\n')
            file.write(f'Not_Taken_Target instruction: \n\t{bb.not_taken_target_instr.strip()}\n')
            file.write('Instruction: '+'\n')
            for line in bb.instr:
                file.write(f'\t{line.strip()}\n')
            file.write('\n\n')

def generate_CFG(basic_block, program_name, output_directory):
    # Create a new Graphviz graph
    graph1 = graphviz.Digraph(format='svg')
    
    # Create a mapping of basic block names to their respective nodes
    bb_nodes = {}

    # Add nodes to the graph
    for bb in basic_block:
        label = f'Basic_block Name: {bb.name}\nIn Function: {bb.func}\nStart address: {bb.start}\nEnd address: {bb.end}\nLength: {bb.length}\nTaken_Target: {bb.taken_target}'
        if bb.not_taken_target is not None:
            label += f'\nNot_Taken_Target address: {bb.not_taken_target}'

        node_name = str(bb.name)
        graph1.node(node_name, label=label, shape='box')
        bb_nodes[bb.name] = node_name 

    # Add edges to the graph
    for i, bb in enumerate (basic_block):
        if bb.taken_target != '':
            if isinstance(bb.taken_target, list):
                for target_str in bb.taken_target:
                    target = target_str.split()[1]
                    for b_num, node_name in bb_nodes.items():
                        if isinstance(b_num, str):
                            num = int(b_num.split()[0])
                            if target == basic_block[num].start:
                                graph1.edge(bb_nodes[bb.name], node_name)
                        else:
                            if target == basic_block[b_num].start:
                                graph1.edge(bb_nodes[bb.name], node_name)

            else:
                for b_num, node_name in bb_nodes.items():
                    if isinstance(b_num, str):
                        num = int(b_num.split()[0])
                        if bb.taken_target == basic_block[num].start:
                            graph1.edge(bb_nodes[bb.name], node_name)
                    else:
                        if bb.taken_target == basic_block[b_num].start:
                            graph1.edge(bb_nodes[bb.name], node_name)
        
        elif bb.taken_target == '' and i+1 < len(basic_block):
            next_bb = basic_block[i+1]
            graph1.edge(bb_nodes[bb.name], bb_nodes[next_bb.name])

        if bb.not_taken_target != '':
            for b_num, node_name in bb_nodes.items():
                if isinstance(b_num, str):
                    num = int(b_num.split()[0])
                    if bb.not_taken_target == basic_block[num].start:
                        graph1.edge(bb_nodes[bb.name], node_name,style='dashed',color = 'red')
                else:
                    if bb.not_taken_target == basic_block[b_num].start:
                        graph1.edge(bb_nodes[bb.name], node_name, style='dashed',color = 'red')
                        
    # Set the output file path
    output_file = os.path.join(output_directory, f'{program_name}_CFG')

    # Render the graph and save it to a file
    graph1.render(filename=output_file, cleanup=True, view=False)  

def convert_to_binary(basic_block, output_file_name, Hash_algorithm, value_length, output_directory):
    '''
    The convert_to_binary function takes in a list of basic blocks and an output file name. 
    The function converts the machine code instructions in each basic block to binary format and writes the binary instructions \
        and a hash value to the output file.
    '''
    binary_file_path = os.path.join(output_directory, output_file_name)
    
    with open (binary_file_path,'w',encoding='utf-8') as file:
        for i in range (len(basic_block)):
            bb_instr = basic_block[i].instr
            address, machine_code, mnemonic, operands =  get_func_machine_code(bb_instr)
        
            # Get binary_machine_code    
            binary_machine_code = []
            for j in range (len(machine_code)):
                int_machine_code = int(machine_code[j], 16)
                bin_machine_code = bin(int_machine_code)[2:].zfill(32)
                binary_machine_code.append(bin_machine_code)

            # Get binary_address
            binary_address = []
            for m in range (len(address)):
                int_address = int(address[m], 16)
                bin_address = bin(int_address)[2:].zfill(16)
                binary_address.append(bin_address)
            
            # Get hash value
            hash_value = calculate_hash_value(binary_machine_code, Hash_algorithm, value_length)

            # Write to file
            file.write(f'Basic_block: {basic_block[i].name}\n')
            file.write(f'bin_basic_block_instructions: \n')
            
            for i in range(len(binary_address)):
                file.write(f'\t{binary_address[i]}: {binary_machine_code[i]}\n')

            file.write(f'hash_value: \n\t{hash_value}\n')
            file.write('\n')

def convert_to_hex(basic_block, output_file, Hash_algorithm, value_length, output_directory):
    '''
    The convert_to_hex function takes in a list of basic blocks and an output file name. 
    The function converts the machine code instructions in each basic block to hexadecimal format and\
        writes the hexadecimal instructions and a hash value to the output file.
    '''
    hex_file_path = os.path.join(output_directory, output_file)
    
    with open(hex_file_path,'w',encoding='utf-8') as file:
        for i in range (len(basic_block)):
            bb_instr = basic_block[i].instr
            address, machine_code, mnemonic, operands =  get_func_machine_code(bb_instr)
        
            # Get hash value
            hash_value = calculate_hash_value(machine_code, Hash_algorithm, value_length)

            # Write to file
            file.write(f'Basic_block: {basic_block[i].name}\n')
            file.write(f'bin_basic_block_instructions: \n')
            
            for i in range(len(address)):
                file.write(f'\t{address[i]}: {machine_code[i]}\n')

            file.write(f'hash_value: \n\t{hash_value}\n')
            file.write('\n')
            
def calculate_hash_value(data, algorithm, value_length):
    binary_data = ''.join(data)
    binary_data = binary_data.encode('utf-8')

    # Create hash object based on selected algorithm
    if algorithm == 'SHA-256':
        hash_type = hashlib.sha256()
    elif algorithm == 'MD5':
        hash_type = hashlib.md5()
    elif algorithm == 'SHA-1':
        hash_type = hashlib.sha1()
    elif algorithm == 'SHA-512':
        hash_type = hashlib.sha512()

    # Calculate hash value
    hash_type.update(binary_data)

    # Get hexdigest of hash value
    hash_value = hash_type.hexdigest()
    
    # Get the hash value of the specified number of digits
    hash_value_spl = hash_value[:int(value_length)]

    return hash_value_spl

def export_results(function_addr_ranges, function_information_file,\
                    all_instr, functions_with_jump_instr_addr, control_transfer_file,bin_file,\
                        basicblock_file_name, basic_block,\
                        block_binary_file_name, hex_file_name, Hash_algorithm, value_length, output_directory, program_name):
    
    # write_functions_information(function_addr_ranges, function_information_file, output_directory)
    
    write_in_may_used_control_transfer_instr(all_instr, functions_with_jump_instr_addr, control_transfer_file, \
                                            bin_file, output_directory, program_name)
    
    write_basic_blocks_to_file(basicblock_file_name, basic_block, output_directory)
    
    convert_to_binary(basic_block, block_binary_file_name, Hash_algorithm, value_length, output_directory)
    
    convert_to_hex(basic_block, hex_file_name, Hash_algorithm, value_length, output_directory)
 
# main(objdump_file)  
 
## UI

def judge_file_type(input_file_path):
    type = None
    with open(input_file_path, 'r') as file:
        lines = file.readlines()
        for line in lines[:15]:
            if line.startswith('#'):
                type = 1
    return type

class CFIEE_UI:
    def __init__(self, master):

        self.master = master
        master.title("CFIEE")
        # master.geometry("800x600") 
        
        # Column 1: Select .elf file and Disassemble
        elf_file_frame = tk.Frame(master)
        elf_file_frame.grid(row=0, column=0, padx=70, pady=150, sticky="nw")
        elf_file_label = tk.Label(elf_file_frame, text="STEP1: Disassemble ELF File", font=("Arial", 10, "bold"))
        elf_file_label.pack(side=tk.TOP, anchor="n", pady=20)

        # File Selection Row
        file_select_frame = tk.Frame(elf_file_frame)
        file_select_frame.pack(side=tk.TOP, anchor="n")
        self.elf_file_select_button = tk.Button(file_select_frame, text="Select ELF file", command=self.select_elf_file, padx=10, pady=5, bd=1, relief="raised")
        self.elf_file_select_button.pack(side=tk.TOP, padx=10, anchor="n")
        self.elf_file_path_var = tk.StringVar()
        self.elf_file_path_label = tk.Label(file_select_frame, textvariable=self.elf_file_path_var, wraplength=150, anchor="w", bg="white", bd=1,\
                                            relief="groove", padx=5)
        self.elf_file_path_label.pack(side=tk.TOP, fill=tk.X, anchor="n", padx=10, pady=20)


        # Disassemble Row
        disassemble_frame = tk.Frame(elf_file_frame)
        disassemble_frame.pack(side=tk.TOP, anchor="n", pady=10)
        self.disassemble_button = tk.Button(disassemble_frame, text="Disassemble", command=self.disassemble_program, font=("Arial", 10, "bold"), bg="lightgray",\
                                                    padx=10, pady=5, bd=1, relief="raised", state=tk.DISABLED)
        self.disassemble_button.pack(side=tk.TOP, anchor="n")
        self.disassemble_label = tk.Label(disassemble_frame, wraplength=200, anchor="w", font=("Arial", 10), justify=tk.LEFT)
        self.disassemble_label.pack(side=tk.TOP, padx=10, fill=tk.X, expand=True)

        # Column 2: Browse file, Preprocess, Analyze, Hash algorithm selection, and Data length selection
        section2_frame = tk.Frame(master)
        section2_frame.grid(row=0, column=2, padx=20, pady=10, sticky="nw")

        # Browse file section
        browse_frame = tk.Frame(section2_frame)
        browse_frame.pack(side=tk.TOP, anchor="n", padx=10, pady=10)

        self.browse_section_label = tk.Label(browse_frame, text="STEP2: Select disassembly file(.txt)", font=("Arial", 10, "bold"))
        self.browse_section_label.pack(side=tk.TOP, anchor="n", pady=10)

        self.browse_button = tk.Button(browse_frame, text="Browse File", command=self.browse_file, bg="white", padx=10, pady=5, bd=1, relief="raised")
        self.browse_button.pack(side=tk.TOP, anchor="n", padx=10, pady=10)

        self.file_path_var = tk.StringVar()
        self.file_path_label = tk.Label(browse_frame, textvariable=self.file_path_var, wraplength=150, anchor="n", bg="white", bd=1, relief="groove", padx=5)
        self.file_path_label.pack(side=tk.TOP, fill=tk.X, anchor="n", padx=10, pady=10)

        self.browse_label = tk.Label(browse_frame, wraplength=200, anchor="w", font=("Arial", 8), justify=tk.LEFT)
        self.browse_label.pack(side=tk.TOP, anchor="n", pady=5)

        # Preprocess section
        preprocess_frame = tk.Frame(section2_frame)
        preprocess_frame.pack(side=tk.TOP, anchor="n", padx=10, pady=10)

        self.preprocess_section_label = tk.Label(preprocess_frame, text="STEP3: Data Preprocess", font=("Arial", 10, "bold"))
        self.preprocess_section_label.pack(side=tk.TOP, anchor="n", padx= 10, pady=10)

        self.preprocess_button = tk.Button(preprocess_frame, text="Preprocess", command=self.rewrite_file, state=tk.DISABLED, bg="lightgray", \
                                                    padx=10, pady=5, bd=1, relief="raised")
        self.preprocess_button.pack(side=tk.TOP, padx=10, pady=10, anchor="n")

        self.rewrite_label = tk.Label(preprocess_frame, wraplength=200, anchor="center", font=("Arial", 8), justify=tk.CENTER)
        self.rewrite_label.pack(side=tk.TOP, fill=tk.X, pady=5)

        self.rewrite_file_path_var = tk.StringVar()

        # Analyze section
        analyze_frame = tk.Frame(section2_frame)
        analyze_frame.pack(side=tk.TOP, anchor='n', padx=10, pady=10)

        self.analyze_section_label = tk.Label(analyze_frame, text="STEP4: File Analyze", font=("Arial", 10, "bold"))
        self.analyze_section_label.pack(side=tk.TOP, anchor="n", pady=10)

        self.analyze_button = tk.Button(analyze_frame, text="Analyze", command=self.analyze_program, state=tk.DISABLED, bg="lightgray", \
                                            padx=10, pady=5, bd=1, relief="raised")
        self.analyze_button.pack(side=tk.BOTTOM, padx=10, pady=5, anchor="n")

        self.analyze_label = tk.Label(analyze_frame, wraplength=200, anchor="center", font=("Arial", 8), justify=tk.CENTER)
        self.analyze_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)


        hash_algorithm_label = tk.Label(analyze_frame, text="Hash:", font=("Arial", 10))
        hash_algorithm_label.pack(side=tk.LEFT, anchor="w",padx=10,pady = 5)

        self.hash_algorithm_var = tk.StringVar()
        hash_algorithm_options = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
        self.hash_algorithm_menu = tk.OptionMenu(analyze_frame, self.hash_algorithm_var, *hash_algorithm_options)
        self.hash_algorithm_menu.pack(side=tk.LEFT, anchor="w", padx = 10, pady = 5)

        data_length_label = tk.Label(analyze_frame, text="Data Length:", font=("Arial", 10))
        data_length_label.pack(side=tk.LEFT, anchor="w", padx=10, pady=5)

        self.data_length_var = tk.StringVar()
        data_length_options = ["8", "16", "32"]
        self.data_length_menu = tk.OptionMenu(analyze_frame, self.data_length_var, *data_length_options)
        self.data_length_menu.pack(side=tk.LEFT, anchor="w", padx=10, pady=5)
        
        # Column 3: Result output
        section3_frame = tk.Frame(master)
        section3_frame.grid(row=0, column=4, padx=10, pady=150, sticky="nw")

        self.output_section_label = tk.Label(section3_frame, text="STEP5: Output Files", font=("Arial", 10, "bold"))
        self.output_section_label.pack(side=tk.TOP, anchor="n", pady=20)

        left_frame = tk.Frame(section3_frame)
        left_frame.pack(side=tk.LEFT, padx=10)

        right_frame = tk.Frame(section3_frame)
        right_frame.pack(side=tk.LEFT, padx=30)
        
        button_width = 15

        basic_block_info_button = tk.Button(left_frame, text="Basic Block Info", command=self.show_basic_block_info, width=button_width)
        basic_block_info_button.pack(side=tk.TOP, pady=5)
        
        bin_bb_button = tk.Button(left_frame, text="Binary Basic Block", command=self.show_bin_bb, width=button_width)
        bin_bb_button.pack(side=tk.TOP, pady=5)

        hex_bb_button = tk.Button(left_frame, text="Hex Basic Block", command=self.show_hex_bb, width=button_width)
        hex_bb_button.pack(side=tk.TOP, pady=5)

        binary_data_button = tk.Button(left_frame, text="Binary Data", command=self.show_binary_data, width=button_width)
        binary_data_button.pack(side=tk.TOP, pady=5)

        transfers_info_button = tk.Button(right_frame, text="Transfers Info", command=self.show_transfers_info, width=button_width)
        transfers_info_button.pack(side=tk.TOP, pady=5)

        cfg_button = tk.Button(right_frame, text="CFG", command=self.show_cfg, width=button_width)
        cfg_button.pack(side=tk.TOP, pady=5)

        transfers_number_button = tk.Button(right_frame, text="Transfers Number", command=self.show_transfers_number, width=button_width)
        transfers_number_button.pack(side=tk.TOP, pady=5)

        function_call_button = tk.Button(right_frame, text="Function Call", command=self.show_function_call, width=button_width)
        function_call_button.pack(side=tk.TOP, pady=5)



        # Add padding between columns
        separator1 = ttk.Separator(master, orient='vertical')
        separator1.grid(row=0, column=1, sticky="ns", padx=20, pady=10)

        separator2 = ttk.Separator(master, orient='vertical')
        separator2.grid(row=0, column=3, sticky="ns", padx=20, pady=10) 

        # Help button
        self.help_button = tk.Button(master, text="Help", command=self.show_help, padx=10, pady=5, bd=1, relief="raised")
        self.help_button.grid(row=1, column=0, padx=20, pady=5,columnspan=1, sticky="s")
        
        # Progress bar (placed at the bottom)
        self.progress_bar = ttk.Progressbar(master, length=300, mode='determinate', orient=tk.HORIZONTAL)
        self.progress_bar.grid(row=1, column=2, padx=10, pady=10, columnspan=1, sticky="s")
        
    def select_elf_file(self):
        
        current_directory = os.getcwd()
        parent_directory = os.path.dirname(current_directory)
        elf_files_directory = os.path.join(parent_directory, "elf_files")

        filetypes = [("ELF Files", "*.elf")]
        file_path = filedialog.askopenfilename(initialdir=elf_files_directory, filetypes=filetypes)
        if file_path:
            self.elf_file_path_var.set(file_path)
            self.disassemble_button.config(state=tk.NORMAL)

    def disassemble_program(self):
        elf_file = self.elf_file_path_var.get()
        if not elf_file:
            self.disassemble_label.config(text="No file selected")
            return
        try:
            output_directory = os.path.join(os.path.dirname(os.getcwd()), "objdump_files")
            if not os.path.exists(output_directory):
                os.makedirs(output_directory)
            output_file = os.path.join(output_directory, os.path.splitext(os.path.basename(elf_file))[0] + "_disassembly.txt")
            process = subprocess.run(["riscv64-unknown-elf-objdump", "-S", elf_file], capture_output=True, text=True)
            with open(output_file, 'w') as file:
                file.write(process.stdout)
            self.disassemble_label.config(text="Disassembly complete.")
            
            self.file_path_var.set(output_file)
            
            self.preprocess_button.config(state=tk.NORMAL)
            self.analyze_button.config(state=tk.NORMAL)
            return output_file
        
        except subprocess.CalledProcessError as e:
            error_message = f"Error: {e.stderr}"
            self.show_error_message(error_message)

    def browse_file(self):
        
        current_directory = os.getcwd()
        parent_directory = os.path.dirname(current_directory)
        elf_files_directory = os.path.join(parent_directory, "objdump_files")

        filetypes = [("TXT Files", "*.txt")]
        objdump_file = filedialog.askopenfilename(initialdir=elf_files_directory, filetypes=filetypes)

        if not objdump_file:
            self.browse_label.config(text="No file selected")
            return

        self.file_path_var.set(objdump_file)
        self.browse_label.config(text="Objdump file selected")
        self.preprocess_button.config(state=tk.NORMAL)
        self.analyze_button.config(state=tk.NORMAL)
        
        type = judge_file_type(objdump_file)
        if type == 1:
            self.browse_label.config(
                text="\nPlease click the 'preprocess' button first")


    def rewrite_file(self):
        objdump_file = self.file_path_var.get()
        file_name = os.path.basename(objdump_file)
        file_directory = os.path.dirname(objdump_file)
        output_file = os.path.join(file_directory, os.path.splitext(file_name)[0] + '_preprocessed.txt')
        self.rewrite_file_path_var.set(output_file)
        self.master.update()
        
        self.progress_bar['value'] = 0 
        self.progress_bar.start()  # startup progress bar
        
        subprocess.run(['python', 'file_preprocess.py', objdump_file, output_file])
        
        self.master.after(100, lambda: self.rewrite_label.config(text="Objdump file has been rewrited!\n \
    File path: {0}\n".format(output_file)))
        
        self.progress_bar.stop()
        self.progress_bar['value'] = 100 
        self.master.update()


    def analyze_program(self):
        input_file = self.file_path_var.get()
        rewrite_file = self.rewrite_file_path_var.get()
        program_name = os.path.basename(input_file)

        # Extract program name
        if "_objdump" in program_name:
            program_name = program_name.split("_objdump")[0]
        elif "_disassembly" in program_name:
            program_name = program_name.split("_disassembly")[0]

        type = judge_file_type(input_file)
        if type == 1:
            self.analyze_label.config(
                text="Please click the 'preprocess' button first and rechoose the new file")
        else:
            t = threading.Thread(target=self.run_analyze_program, args=(input_file, rewrite_file, program_name))
            t.start()


    def run_analyze_program(self, input_file, rewrite_file, program_name):
        try:
            self.progress_bar['value'] = 0

            hash_algorithm = self.hash_algorithm_var.get()
            result_length = self.data_length_var.get()

            if not hash_algorithm or not result_length:
                self.analyze_label.config(
                    text="Please select hash algorithm and result length")
                return

            file_to_analyze = rewrite_file if os.path.exists(
                rewrite_file) else input_file
            self.progress_bar.start()  # startup progress bar
            self.analyze_label.config(text="Analyzing...")

            # Execute analysis program
            main(file_to_analyze, hash_algorithm, result_length, program_name)

            self.progress_bar.stop()
            self.progress_bar['value'] = 100

            self.analyze_label.config(text="Complete!")
                    
        except Exception as e:
            error_message = f"Error: {e}"
            self.show_error_message(error_message)
        
    def show_help(self):
        try:
            # Open .md files with the default application associated with the system
            readme_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Readme.md'))
            subprocess.Popen(['start', '', readme_path], shell=True)
        except FileNotFoundError:
            print("Unable to find a default application to open the .md file.")

    def show_basic_block_info(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        lastest_modification_time = 0
        bb_info_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("basic_block.txt"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > lastest_modification_time:
                    lastest_modification_time = file_modification_time
                    bb_info_file_path = file_path
        
        if bb_info_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:
            try:
                os.startfile(bb_info_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_binary_data(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        lastest_modification_time = 0
        bin_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith(".bin"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > lastest_modification_time:
                    lastest_modification_time = file_modification_time
                    bin_file_path = file_path
            
        if bin_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:
            try:
                subprocess.Popen(["notepad.exe", bin_file_path])
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_transfers_info(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        lastest_modification_time = 0
        transfers_info_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("transfers.txt"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > lastest_modification_time:
                    lastest_modification_time = file_modification_time
                    transfers_info_file_path = file_path
        
        if transfers_info_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
            
        else:
            try:
                os.startfile(transfers_info_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_cfg(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        cfg_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith(".svg"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    cfg_file_path = file_path
        
        if cfg_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:
            try:
                os.startfile(cfg_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
        
    def show_transfers_number(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        transfers_number_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("per_function.svg"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    transfers_number_file_path = file_path
                
            
        if transfers_number_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:    
            try:
                os.startfile(transfers_number_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
        
    def show_function_call(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        function_call_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("call_relationship.svg"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    function_call_file_path = file_path

            
        if function_call_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:    
            try:
                os.startfile(function_call_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_bin_bb(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        bin_bb_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("bin_basic_block_inf.txt"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    bin_bb_file_path = file_path
        
        if bin_bb_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:
            try:  
                os.startfile(bin_bb_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_hex_bb(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        hex_bb_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("hex_basic_block_inf.txt"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    hex_bb_file_path = file_path
        
        if hex_bb_file_path is None:
            error_message = "Error:File not found"
            self.show_error_message(error_message)
        else:
            try:
                os.startfile(hex_bb_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
        
    def show_error_message(self, error_message):
        error_window = tk.Toplevel(self.master)
        error_window.title("Error")
        error_window.geometry("400x300")

        scrollbar = tk.Scrollbar(error_window)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
 
        error_text = tk.Text(error_window, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        error_text.pack(fill=tk.BOTH, expand=True)

        scrollbar.config(command=error_text.yview)

        error_text.insert(tk.END, error_message)

if __name__ == "__main__":
    root = tk.Tk()
    gui = CFIEE_UI(root)
    root.mainloop()




