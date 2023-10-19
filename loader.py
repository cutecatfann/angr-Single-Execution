import angr
import claripy

# STEPS: Run
# nm tests/test_pointer
# Check in the print statement what you are called
# source myenv/bin/activate


def execute_func(binary_path, func_name):
    # Load the binary
    proj = angr.Project(binary_path, load_options={'auto_load_libs': False})

    # Get the CFG to find the function
    cfg = proj.analyses.CFG()

    # Print the list of functions
    print("Functions in the binary:")
    for name, func in cfg.functions.items():
        print(name, func)

    # Find the function by name
    func = cfg.functions.function(name=func_name)
    if func is None:
        print(f"Function {func_name} not found")
        return

    # Create a state at the start of the function
    state = proj.factory.blank_state(addr=func.addr)

    # Make the function parameters symbolic
    args = []
    for arg in func.prototype.args:
        # If the argument is a pointer, make the pointee symbolic
        if isinstance(arg, angr.sim_type.SimTypePointer):
            pointee = claripy.BVS(f"{arg}_pointee", arg.size * 8)
            ptr = state.heap.alloc(arg.size)
            state.memory.store(ptr, pointee)
            args.append(ptr)
        else:
            # Otherwise, make the argument itself symbolic
            sym_arg = claripy.BVS(f"{arg}_arg", arg.size * 8)
            args.append(sym_arg)

    # Create a call state for the function
    call_state = state.copy()
    call_state.regs.sp = call_state.regs.sp - \
        0x8 * len(args)  # Adjust stack pointer
    for i, arg in enumerate(args):
        call_state.memory.store(call_state.regs.sp + 0x8 * i, arg)

    # Setup the simulation manager
    simgr = proj.factory.simulation_manager(call_state)

    # Run the simulation
    simgr.run()

    # Show the results
    print(f"Results for function {func_name}:")
    for i, res in enumerate(simgr.deadended):
        print(f"Result {i + 1}: {res}")


# Example usage
execute_func('tests/test_pointer', 'sub_100003f70')
