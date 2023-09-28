import angr

def make_memory_symbolic(state, addr, size):
    """
    Make a memory region symbolic in the given state.

    :param state: The angr state object.
    :param addr: The address of the memory region to make symbolic.
    :param size: The size (in bytes) of the memory region.

    :return: None
    """
    symbolic_data = state.solver.BVS("symbolic_data", size * 8)
    state.memory.store(addr, symbolic_data, size=size)


def handle_call_state(state, return_address):
    """
    Make the return address symbolic and set it in the state's registers.

    :param state: The angr state object.
    :param return_address: The symbolic return address.

    :return: None
    """
    make_memory_symbolic(state, return_address, 4)
    state.registers.store('eax', return_address)


def symbolic_execution_for_function(proj, addr, func):
    """
    Perform symbolic execution for a given function.

    :param proj: The angr project object.
    :param addr: The address of the function to execute symbolically.
    :param func: The function object representing the function.

    :return: A list of deadended states resulting from symbolic execution.
    """
    print("Executing Function:", func.name)

    # Create a blank state for symbolic execution
    state = proj.factory.blank_state(addr=addr)

    # Set function parameters as symbolic (MODIFY THIS)
    # For now, assume all parameters are 32-bit integers
    for param in func.arguments:
        state.registers.store(param[1], state.solver.BVS(param[0], 32))

    # Create a simulation manager and run symbolic execution until ret instruction
    simgr = proj.factory.simgr(state)

    # Symbolically execute until it reaches the ret instruction or a call to another function
    while simgr.active:
        current_instruction = simgr.active[0].addr

        # Check if the current instruction is outside the main binary's address space
        if current_instruction < main_binary_start or current_instruction > main_binary_end:
            simgr.move(from_stash='active', to_stash='deadended')
        else:
            # Check if the current instruction is a valid function address
            if current_instruction in valid_function_addresses:
                block = proj.factory.block(current_instruction)

                # Check if the current basic block ends in a call instruction
                if any(proj.factory.block(next_addr).vex.jumpkind.startswith('Ijk_Call') for next_addr in block.vex.constant_jump_targets):
                    simgr.move(from_stash='active', to_stash='deadended')
                    
                    return_address = state.solver.BVS('return_address', 32)
                    handle_call_state(state, return_address)
                else:
                    simgr.step()
            else:
                simgr.move(from_stash='active', to_stash='deadended')

    deadended_states = simgr.deadended
    return deadended_states


if __name__ == "__main__":
    # Create an Angr project with auto_load_libs=False
    proj = angr.Project('tests/hello', auto_load_libs=False)

    # Specify the address for symbolic execution
    addr = proj.entry
    
    # Define memory regions for the CFG
    regions = [(0x401020, 0x40103f)]

    # Create a blank state for symbolic execution
    state = proj.factory.blank_state(addr=addr)
    #main_addr = 0x401234
    #state = proj.factory.blank_state(addr=main_addr)

    # Add state options to handle unconstrained regions
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

    # Generate a static CFG quickly, but only for the main binary
    main_binary_start = proj.loader.main_object.min_addr
    main_binary_end = proj.loader.main_object.max_addr

    # Create a CFG with specified memory regions
    cfg = proj.analyses.CFGFast(regions=regions)  #
    
    # Get a set of valid function addresses
    valid_function_addresses = set(cfg.kb.functions.keys())

    for addr, func in cfg.kb.functions.items():
        deadended_states = symbolic_execution_for_function(proj, addr, func)

        # Process the deadended states here 
# if __name__ == "__main__":
#     # Create an Angr project with auto_load_libs=True to automatically load libraries
#     proj = angr.Project('tests/test_binary', auto_load_libs=True)

#     # Specify the address of the entry point
#     entry_addr = proj.entry

#     # Create a blank state for symbolic execution with the entry point as the start address
#     state = proj.factory.blank_state(addr=entry_addr)

#     # Add state options to handle unconstrained regions
#     state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
#     state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
#     state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
#     state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

#     # Create a CFG for the entire binary (including libraries)
#     cfg = proj.analyses.CFG()

#     # Get a set of valid function addresses
#     valid_function_addresses = set(cfg.kb.functions.keys())

#     for addr, func in cfg.kb.functions.items():
#         deadended_states = symbolic_execution_for_function(proj, addr, func)

#         # Process the deadended states here
