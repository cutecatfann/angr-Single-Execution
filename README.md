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

## Ongoing Work:

- **Deadended State Processing**: The states that reach the `ret` instruction, termed `deadended` states, are yet to be processed and analyzed.
- **Parameter Handling**: The handling of function parameters, particularly their types and sizes, will be refined further.
- **Performance Optimization**: As with any symbolic execution task, performance can be a concern. Future iterations will work on optimizing the execution flow and possibly parallelizing certain tasks.

## Feedback & Contributions:

Feedback, bug reports, and pull requests are welcomed. Feel free to open an issue or submit a pull request if you believe there are enhancements to be made. Your contributions can significantly aid in the ongoing refinement and evolution of this research project.

---

**Note**: This is a research project and while utmost care has been taken to ensure accuracy, it is always advisable to validate results in a controlled environment, especially before deploying or utilizing them in production or critical scenarios.
