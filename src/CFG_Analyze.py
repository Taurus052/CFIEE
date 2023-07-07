'''
Author: 'Taurus052' 'qq_52550864@gitcode.net'
Date: 2023-05-08 14:14:15
LastEditTime: 2023-07-07 14:59:39
'''

# import re
import os
import hashlib
# branch instructions
branch_inst = ["beq", "bne", "blt", "bltu", "bge", "bgeu", "beqz", "bnez", "bltz", "blez", "bgtz", "bgez", "bgt", "bgtu", "ble", "bleu"]
# jump instruction
unconditional_jump_inst = ["jal", "j"]
indirect_jump_inst = ["jr", "jalr"]

# objdump_file = 'objdump_rewrite.txt'

#获取当前脚本所在的目录路径
current_dir = os.path.dirname(os.path.abspath(__file__))

#切换到当前目录
os.chdir(current_dir)

def main(objdump_file):
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
    
    function_call_relationship = get_function_call_relationship(function_call_instr, function_addr_ranges)
    
    return_target = get_return_relationship(function_call_relationship, ret_instr_addr, function_call_instr, \
                                                all_instr, function_addr_ranges)
        
    used_function_instr = extract_used_function_instr(function_instr, visited_functions)
    
    address, machine_code, mnemonic, operands = get_func_machine_code(used_function_instr)
    
    end_addr_list, branch_or_jump_target_addr, \
        branch_taken_start_addr, all_taken_target_addr, order_start_addr_list= \
            get_the_addr_information_of_all_function(address, mnemonic, operands, function_addr_ranges)
    
    
    basic_block = create_basic_blocks_in_order(order_start_addr_list, end_addr_list, used_function_instr, function_addr_ranges,\
                                                ret_instr_addr,return_target)
                                       
    basic_block =  create_basic_blocks_start_with_taken_target(all_taken_target_addr, basic_block, order_start_addr_list, used_function_instr)
    
    sorted_basic_blocks =  sort_basic_blocks(basic_block)
    
    export_results(function_addr_ranges, 'function_information.txt',\
                    all_instr, sorted_functions_with_jump_instr_addr, 'may_used_control_transfers.txt',\
                        'basic_block.txt', sorted_basic_blocks,\
                        'bin_basic_block_inf.txt', 'hex_basic_block_inf.txt')


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

def write_functions_information(function_addr_ranges, output_file):
    with open(output_file, 'w') as f:
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
        if range(len(lines)) == 1:
            if line.split()[2] == 'jal' or line.split()[2] ==  'j' :
                    operand = line.split()[3]
                    if ',' in operand:#jal
                        jump_target = operand.split(',')[1]
                        call_instrs.append(line)
                    elif ',' not in operand:#j
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
                if ',' in operand:#jal
                    jump_target = operand.split(',')[1]
                    call_instrs.append(line)
                elif ',' not in operand:#j
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

# def extract_function_before_xx(objdump_file, function_xx):
#     '''
#     The 'extract_function_before_xx' function takes in an objdump file and the name of a function as input data. 
#     The function returns a list of the names of all functions that appear before the input function in the objdump file.
#     '''
    
#     function_names = []
#     with open (objdump_file, 'r') as file:
#         lines = file.readlines()
#         for line in lines:
#             line = line.strip()
#             if ('>:') in line and function_xx not in line:
#                 function_names.append(line.split()[-1][:-1])
#             elif function_xx in line:
#                 break
#     return function_names

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

def get_function_call_relationship(function_call_instr, function_addr_ranges):
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
            jump_target = operand.split(',')[-1]
            
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
                            function_call_relationship[caller_func_name] = [callee_func_name + ' j']
                        break 

    # Remove duplicates from the function call relationship
    for caller_func_name in function_call_relationship:
        function_call_relationship[caller_func_name] = list(set(function_call_relationship[caller_func_name]))
    # Sort the function call relationship based on the start address of the caller functions
    function_call_relationship = {k: v for k, v in sorted(function_call_relationship.items(), key=lambda item: int(function_addr_ranges[item[0]][0], 16))}
    
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
                if len(func_name.split()) != 1 and func_name.split()[1] == 'j':
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
                func_n2 = func.split()[1]
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
    with open(objdump_file,'r',encoding='utf-8') as file:
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

def write_in_may_used_control_transfer_instr(all_instr, functions_with_jump_instr_addr, output_file):
    
    with open (output_file,'w',encoding='utf-8') as file:
        for func_name in functions_with_jump_instr_addr:
            file.write('\n' + func_name + ':\n'+'\n')
            for line in functions_with_jump_instr_addr[func_name]:
                addr, taken_target = line.split(',')
                target_line_num = None

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
                        file.write('j/b_instr: '+all_instr[jump_instr_line_num] + '\n')
                        file.write('t_instr:   '+all_instr[target_line_num] + '\n')
                        file.write('\n')

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

def get_the_addr_information_of_all_function(address, mnemonic, operands, function_addr_ranges):
    '''
    Get address information for all functions.

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
            
        if address[i] in func_end_addr_list and i+1 < len(mnemonic):
            end_addr_list.append(address[i])
            order_start_addr_list.append(address[i+1])

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
                branch_or_jump_target_addr.append(operand[0]+' j')   
                all_taken_target_addr.append(address[i] + ',' + operand[-1])

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
            # basic_block[i].taken_target = operands
            basic_block[i].taken_target = 'FFFF'
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

def write_basic_blocks_to_file(file_name, basic_block):
    with open(file_name, 'w', encoding='utf-8') as file:
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

def convert_to_binary(basic_block, output_file_name):
    '''
    The convert_to_binary function takes in a list of basic blocks and an output file name. 
    The function converts the machine code instructions in each basic block to binary format and writes the binary instructions \
        and a hash value to the output file.
    '''
    
    with open (output_file_name,'w',encoding='utf-8') as file:
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
            hash_value = calculate_hash_value(binary_machine_code, 'md5', 16)

            # Write to file
            file.write(f'Basic_block: {basic_block[i].name}\n')
            file.write(f'bin_basic_block_instructions: \n')
            
            for i in range(len(binary_address)):
                file.write(f'\t{binary_address[i]}: {binary_machine_code[i]}\n')

            file.write(f'hash_value: \n\t{hash_value}\n')
            file.write('\n')

def convert_to_hex(basic_block, output_file):
    '''
    The convert_to_hex function takes in a list of basic blocks and an output file name. 
    The function converts the machine code instructions in each basic block to hexadecimal format and\
        writes the hexadecimal instructions and a hash value to the output file.
    '''
    with open(output_file,'w',encoding='utf-8') as file:
        for i in range (len(basic_block)):
            bb_instr = basic_block[i].instr
            address, machine_code, mnemonic, operands =  get_func_machine_code(bb_instr)
        
            # Get hash value
            hash_value = calculate_hash_value(address, 'md5', 16)

            # Write to file
            file.write(f'Basic_block: {basic_block[i].name}\n')
            file.write(f'bin_basic_block_instructions: \n')
            
            for i in range(len(address)):
                file.write(f'\t{address[i]}: {machine_code[i]}\n')

            file.write(f'hash_value: \n\t{hash_value}\n')
            file.write('\n')
            
def calculate_hash_value(bin_data, algorithm, value_length):
    binary_data = ''.join(bin_data)
    binary_data = binary_data.encode('utf-8')

    # Create hash object based on selected algorithm
    if algorithm == 'sha256':
        hash_type = hashlib.sha256()
    elif algorithm == 'md5':
        hash_type = hashlib.md5()
    elif algorithm == 'sha1':
        hash_type = hashlib.sha1()
    elif algorithm == 'sha512':
        hash_type = hashlib.sha512()

    # Calculate hash value
    hash_type.update(binary_data)

    # Get hexdigest of hash value
    hash_value = hash_type.hexdigest()
    
    # Get the hash value of the specified number of digits
    hash_value_spl = hash_value[:value_length]

    return hash_value_spl

def export_results(function_addr_ranges, function_information_file,\
                    all_instr, functions_with_jump_instr_addr, control_transfer_file,\
                        basicblock_file_name, basic_block,\
                        block_binary_file_name, hex_file_name  ):
    
    write_functions_information(function_addr_ranges, function_information_file)
    
    write_in_may_used_control_transfer_instr(all_instr, functions_with_jump_instr_addr, control_transfer_file)
    
    write_basic_blocks_to_file(basicblock_file_name, basic_block)
    
    convert_to_binary(basic_block, block_binary_file_name)
    
    convert_to_hex(basic_block, hex_file_name)
 
# main(objdump_file)  
 
## UI
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import threading
import webbrowser
import subprocess

# ttk.Style().theme_names()

class ProgramAnalyzerUI:
    def __init__(self, master):
        self.master = master
        master.title("CFG Information Analyzer")
        master.geometry("600x400")  # 设置窗口的默认大小

        # 添加文件选择器
        self.file_path_var = tk.StringVar()
        self.file_path_label = tk.Label(master, textvariable=self.file_path_var)
        self.file_path_label.pack(pady=10)

        # 创建一个框架用于容纳按键
        button_frame = tk.Frame(master)
        button_frame.pack(side=tk.TOP, pady=5)

        self.rewrite_button = tk.Button(button_frame, text="Rewrite file", command=self.rewrite_file)
        self.rewrite_button.pack(side=tk.TOP, pady=10)  # 设置按键的位置以及与周围的间距
        
        self.browse_button = tk.Button(button_frame, text="Browse file", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT, padx=6, pady=6)  # 设置按键的位置以及与周围的间距

        self.analyze_button = tk.Button(button_frame, text="Analyze", command=self.analyze_program)
        self.analyze_button.pack(side=tk.LEFT, padx=6, pady=6)  # 设置按键的位置以及与周围的间距

        # 添加进度条
        self.progress_bar = ttk.Progressbar(master, length=250, mode='determinate')
        self.progress_bar.pack(pady=20)  # 设置进度条与周围的间距

        # 添加帮助按钮
        self.help_button = tk.Button(master, text="Help", command=self.show_help)
        self.help_button.pack(pady=10)
        
        # 添加自定义文本
        self.custom_text = tk.Label(master, text="Github @Taurus052", anchor="s")
        self.custom_text.pack(side=tk.BOTTOM, pady=10)
        
        # 添加状态标签
        self.status_label = tk.Label(master, text="")
        self.status_label.pack(pady=6)

    def rewrite_file(self):
        input_file = filedialog.askopenfilename()
        file_name = os.path.basename(input_file)
        file_directory = os.path.dirname(input_file)
        output_file = os.path.join(file_directory, os.path.splitext(file_name)[0] + '_rewrite.txt')
        self.file_path_var.set(input_file)
        self.master.update()
        
        self.progress_bar['value'] = 0 
        self.progress_bar.start()  # startup progress bar
        subprocess.run(['python', 'objdump_file_rewrite.py',input_file, output_file])
        self.master.after(100, lambda: self.status_label.config(text="Objdump file has been rewrited!\n \
File path: imput_file_path\ xxxxx_rewrite.txt\nPlease click 'Browse file' to select the file."))
        self.progress_bar.stop()
        self.progress_bar['value'] = 100 
        self.master.update()
    
    def browse_file(self):
        objdump_file = filedialog.askopenfilename()
        self.file_path_var.set(objdump_file)
        
        self.status_label.config(text="Objdump file selected")

    def analyze_program(self):
        # 创建线程运行分析程序，防止界面阻塞
        t = threading.Thread(target=self.run_analyze_program)
        t.start()

    def run_analyze_program(self):
        try:
            self.progress_bar['value'] = 0 
            self.progress_bar.start()  # startup progress bar
            
            self.status_label.config(text="Analyzing...")

            # Execute analysis program
            main(self.file_path_var.get())

            self.progress_bar.stop()
            self.progress_bar['value'] = 100 
            
            self.status_label.config(text="Complete!")
        except Exception as e:
            self.progress_bar.stop()
            self.status_label.config(text="Error!")

    def show_help(self):
        try:
            # Open .md files with the default application associated with the system
            subprocess.Popen(['start', '', 'Readme.md'], shell=True)
        except FileNotFoundError:
            print("Unable to find a default application to open the .md file.")

root = tk.Tk()
program_analyzer_ui = ProgramAnalyzerUI(root)
root.mainloop()




