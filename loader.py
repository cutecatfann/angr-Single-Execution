import angr
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypePointer
import claripy
import logging

# Filter out warnings from cle.backends.macho.macho
logging.getLogger("cle.backends.macho.macho").setLevel(logging.ERROR)

# Steps to run:
# nm tests/test_pointer
# Check in the print statement what you are called
# source myenv/bin/activate

def allocate_heap(state, size):
    current_brk = state.solver.eval(state.posix.brk)
    new_brk = current_brk + size
    state.posix.brk = new_brk
    return current_brk

def execute_func(binary_path, func_name):
    # Load the binary
    proj = angr.Project(binary_path, load_options={'auto_load_libs': False})

    # Get the CFG to find the function
    cfg = proj.analyses.CFG()

    # Print the list of functions
    # print("Functions in the binary:")
    # for name, func in cfg.functions.items():
    #     print(name, func)

    # Find the function by name
    found = False
    for addr, func in cfg.functions.items():
        if func.name == func_name:
            found = True
            break

    if not found:
        print(f"Function {func_name} not found")
        return

    # Automatically get the function prototype. Uncomment for less accurate results
    # prototype = proj.kb.functions[addr].prototype
    # if prototype is None:
    #     print(f"Prototype for function {func_name} not found")
    #     return

    # Manually specify the prototype for the function
    # Here, it specifies the SinType of the function
    # First is the parameter type, second is the return type

    # For pointer parameter and integer returns
    prototype = SimTypeFunction([SimTypePointer(SimTypeInt())], SimTypeInt())
    
    # For int parameter and int return
    # prototype = SimTypeFunction(SimTypeInt(), SimTypeInt())
    proj.kb.functions[addr].prototype = prototype

    # Create a state at the start of the function
    state = proj.factory.blank_state(addr=func.addr)

    # Make the function parameters symbolic
    args = []
    if isinstance(func.prototype.args, list):
        for arg in func.prototype.args:
            # If the argument is a pointer, make the pointee symbolic
            if isinstance(arg, angr.sim_type.SimTypePointer):
                pointee_size = proj.arch.bytes * 8
                pointee = claripy.BVS(f"{arg}_pointee", pointee_size)
                ptr = allocate_heap(state, proj.arch.bytes)

                state.memory.store(ptr, pointee)
                args.append(ptr)
            else:
                # Otherwise, make the argument itself symbolic
                sym_arg = claripy.BVS(f"{arg}_arg", arg.size * 8)
                args.append(sym_arg)
    else:
        # If there's only one argument, make it symbolic
        arg = func.prototype.args
        if isinstance(arg, angr.sim_type.SimTypePointer):
            pointee_size = proj.arch.bytes * 8
            pointee = claripy.BVS(f"{arg}_pointee", pointee_size)
            ptr = allocate_heap(state, proj.arch.bytes)
            state.memory.store(ptr, pointee)
            args.append(ptr)
        else:
            sym_arg = claripy.BVS(
                f"{arg}_arg", arg.with_arch(proj.arch).size * 8)
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
    # Uncomment lines as desired
    print(f"Results for function {func_name}:")
    for i, res in enumerate(simgr.deadended):
        print(f"Result {i + 1}: {res}")
    print(f"Results for function {func_name}:")
    print(f"Deadended: {len(simgr.deadended)}")
    print(f"Active: {len(simgr.active)}")
    print(f"Errored: {len(simgr.errored)}")
    for i, res in enumerate(simgr.deadended):
        print(f"Deadended {i + 1}: {res}")
    for i, res in enumerate(simgr.active):
        print(f"Active {i + 1}: {res}")
    for i, res in enumerate(simgr.errored):
        print(f"Errored {i + 1}: {res}")

    # Uncomment for a pointer type function
    # prototype = proj.kb.functions[addr].prototype
    # print("Prototype:", prototype)

    print("Register values:")
    for reg_name, reg_value in state.regs.__dict__.items():
        print(f"{reg_name}: {reg_value}")

    # Adjust based on your program if desired
    # start_addr = 0x400000
    # size = 0x1000

    # # Dump memory contents
    # memory_contents = state.memory.load(start_addr, size)
    # print(f"Memory contents at 0x{start_addr:x}:")
    # print(memory_contents)
    
    # print("Register values:")
    # for reg in ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]:
    #     print(f"{reg}: {state.registers.load(reg)}")


# Uncomment below line for test_pointer binary
execute_func('tests/test_pointer', 'sub_100003f70')

# Uncomment below line for test_return binary
# execute_func('tests/test_ret', 'sub_100003f80')
