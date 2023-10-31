# Symbolic Execution with angr: Single Function Analysis

This research project utilizes the `angr` framework to execute functions symbolically in isolation. Our approach focuses on evaluating a single function at a time, with other function calls being represented by symbolic values, rather than executing the entire program flow. When a function call within the target function is encountered, its return value is made symbolic. Similarly, any parameters to these function calls passed by reference are also considered symbolic.

### Technologies and Tools Used:
- **angr**: A binary analysis framework.
- **Ghidra**: Utilized for disassembling binary code.
- **NM**: Employed for function analysis.

### Methodology
The code instructs `angr` to run a single function by providing the binary location of that function. It steps through the `angr` disassembler to find the desired function, generating a prototype based on input and return types using `SimTypes` provided by `angr`. The code then creates a standard `angr` state, with parameters being made symbolic. For parameters that are pointers, the pointee becomes symbolic; otherwise, the argument itself is made symbolic. A call state for the function is then created, and the `angr` simulation symbolically executes the function, subsequently printing out the results.

### Results
Months of working with `angr` has shown that it does not natively support this type of analysis. Changing types to symbolic results in uninitialized memory, as `angr` does not support changing types to symbolic and wipes the memory at those locations.

The test function output showed the following warnings and results:

```
python3 loader.py
WARNING | ... | The program is accessing register with an unspecified value.
WARNING | ... | Filling register rbp with 8 unconstrained bytes referenced from ...
WARNING | ... | Filling register rdi with 8 unconstrained bytes referenced from ...
WARNING | ... | Exit state has over 256 possible solutions. Likely unconstrained; skipping.
Results for function sub_100003f80:
Deadended: 0
Active: 0
Errored: 0
Register values:
state: <SimState @ 0x100003f80>
WARNING | ... | Filling memory at 0x400000 with 4096 unconstrained bytes referenced from ...
Memory contents at 0x400000:
<BV32768 mem_400000_4_32768{UNINITIALIZED}>
```

The output indicates that the program is dealing with unspecified values, and `angr` is filling in unconstrained symbolic variables as a coping mechanism. This results in over 256 possible solutions for the exit state, making it likely unconstrained. This could be seen as a limitation of the current methodology when it comes to dealing with uninitialized memory and symbolic variables.

### How to Run
1. Compile a test file into a binary using GCC.
2. Run the binary through NM or another decompiler to get function addresses.
3. Add the binary name, path, and function address to the last line in the code: `execute_func('tests/test_ret', 'sub_100003f80')`.
4. If needed, adjust the prototype types (e.g., `prototype = SimTypeFunction(SimTypeInt(), SimTypeInt())`) to fit the function you are executing.
5. Create a Python virtual environment and activate it.
6. Install `angr` within the virtual environment.
7. Run `python3 loader.py`.
8. You can uncomment print statements at the end as you please.
