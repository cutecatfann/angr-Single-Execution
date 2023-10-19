# Symbolic Execution with angr: Focused Function Analysis

This research project explores a focused approach to symbolic execution using the `angr` framework, targeting one function at a time. Rather than executing an entire program flow, the aim is to symbolically evaluate each function in isolation. When a function call within the target function is encountered, instead of diving into it, the return value is simply marked as symbolic. Similarly, parameters to these function calls passed by reference are considered symbolic.

### Technologies and Tools Used:
- **angr**: A powerful platform-agnostic binary analysis framework.
- **Ghidra**: Used for disassembly of binary code.

## Methodology:

1. **Function Enumeration**: Use `angr` to retrieve a list of all the functions in the target binary.
2. **Symbolic Execution**: Write code that allows for the symbolic execution of each enumerated function, while treating their parameters as symbolic entities.
3. **Function Call Handling**: Modify or extend the `angr` codebase to treat function calls within the target function as explained above, making their return values and reference-passed parameters symbolic.
4. **Testing**: Develop tests to validate this approach. Execute these tests with both the traditional symbolic execution mechanism and this project's method to gauge differences.

## Code Overview:

The code provided serves as a foundation for the aforementioned methodology. The code illustrates:
- Creating an `angr` project.
- Generating a Control Flow Graph (CFG) for the target binary.
- Iterating through each function and symbolically executing it, making parameters symbolic and handling internal function calls as discussed.

Note: This code is a work in progress and will continue to evolve.

## How to Use:

1. Ensure `angr` is installed and set up in your Python environment.
2. Use the provided code as a foundation or reference for your own symbolic execution tasks with `angr`.
3. Make sure to point to the correct binary with the `angr.Project` instantiation.
4. Execute the script to begin the function-by-function symbolic execution.

