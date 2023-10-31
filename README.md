# Symbolic Execution with angr: Single Function Analysis
#### Research was completed by Mimi Pieper under the direction of David Pouliot, PhD, at Southern Oregon University

This research project uses the `angr` framework to symbolically execute each function in isolation, as opposed to the entire program flow. When a function call within the function of interest is encountered, we avoid diving deep into its execution. Instead, the return value is marked as symbolic. Parameters passed by reference to these function calls are also treated as symbolic.

### Technologies and Tools:
- **angr**: A powerful binary analysis framework.
- **Ghidra**: A tool for disassembling binary code.
- **NM**: Utilized for function analysis.

### Methodology:
1. Direct `angr` to execute one function at a time by specifying the binary location of the function. This prevents `angr` from delving into supporting libraries.
2. Traverse the `angr` disassembler until the desired function is located. If the function isn't found, the process halts.
3. Generate a prototype for the function, basing it on the input and return types. This step employs SimTypes from `angr`.
4. Establish a standard `angr` state, and iterate over the parameters to mark them as symbolic. If a parameter is a pointer, its reference is made symbolic; otherwise, the argument itself is rendered symbolic.
5. Create a call state for the function and initiate the `angr` simulation for symbolic execution.
6. Display the execution results.

### Results:
From extensive experimentation, it's evident that `angr` doesn't natively support this specific type of analysis. Making types symbolic often leads to uninitialized memory. The logs suggest that when a type is converted to symbolic, `angr` tends to erase the memory at the designated locations.

Following are the results from the test:
```
python3 loader.py
... [multiple WARNING lines indicating access to unspecified values and uninitialized regions]
Results for function sub_100003f80:
Deadended: 0
Active: 0
Errored: 0
Register values:
state: <SimState @ 0x100003f80>
...
Memory contents at 0x400000:
<BV32768 mem_400000_4_32768{UNINITIALIZED}>
```
The above output shows that the symbolic execution results in numerous warnings, mostly related to accessing registers with unspecified values. This is consistent with the observation of memory being wiped when types are converted to symbolic. Furthermore, the results for the function `sub_100003f80` show zero states in the categories of Deadended, Active, and Errored, suggesting the symbolic execution didn't branch out or encounter errors. Memory at address `0x400000` remains uninitialized.

### Test File:
```c
int func1(int val){
    return val + 1;
}

void main(){
    int mainval = func1(5);
}
```

### How to Run:
1. Acquire a test file and compile it using GCC to generate a binary.
2. Decompile the binary with NM or a similar tool to retrieve function addresses.
3. Update the code with the binary name, path, and function address: `execute_func('tests/test_ret', 'sub_100003f80')`.
4. If necessary, modify the Prototype types (e.g., `prototype = SimTypeFunction(SimTypeInt(), SimTypeInt())`) to align with the function you're analyzing.
5. Set up a Python virtual environment and activate it.
6. Install `angr`.
7. In the virtual environment, execute `python3 loader.py`. Adjust print statements as required.

Note: Ensure you're working within the virtual environment when running the analysis to avoid dependency issues.
