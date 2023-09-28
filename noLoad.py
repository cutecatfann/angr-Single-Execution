import angr

# Create an Angr project with auto_load_libs=False
proj = angr.Project('tests/hello', auto_load_libs=False)

# Specify the address for symbolic execution
addr = proj.entry

# Define memory regions for the CFG
regions = [(0x401020, 0x40103f)]

# Create a blank state for symbolic execution
state = proj.factory.blank_state(addr=addr)

# Add state options to handle unconstrained regions
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

# Generate a static CFG quickly, but only for the main binary
main_binary_start = proj.loader.main_object.min_addr
main_binary_end = proj.loader.main_object.max_addr

# Create a CFG with specified memory regions
cfg = proj.analyses.CFGFast(start=main_binary_start, end=main_binary_end, regions=regions)

# Helper function to make a memory region symbolic
def make_memory_symbolic(state, addr, size):
    symbolic_data = state.solver.BVS("symbolic_data", size * 8)
    state.memory.store(addr, symbolic_data, size=size)

# Get a set of valid function addresses
valid_function_addresses = set(cfg.kb.functions.keys())

# Iterate through the function list and symbolically execute each function
for addr, func in cfg.kb.functions.items():
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
                    make_memory_symbolic(state, return_address, 4)
                    state.registers.store('eax', return_address)
                else:
                    simgr.step()
            else:
                simgr.move(from_stash='active', to_stash='deadended')

    # Collect the deadended states (states that reached the ret instruction)
    deadended_states = simgr.deadended

    # TODO: process the deadended states
