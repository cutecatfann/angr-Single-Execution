# Symbolic Execution with angr: Single Function Analysis
#### Research was completed by Mimi Pieper under the direction of David Pouliot, PhD, at Southern Oregon University

This project utilized the `angr` binary analysis framework to execute functions symbolically in isolation, thereby preventing state explosion. We modified `angr` to handle function calls within the analyzed function by marking their return values and referenced parameters as symbolic.

### Technologies and Tools:
- **angr**: Binary analysis framework.
- **Ghidra**: Disassembly and reverse engineering tool.
- **NM**: Binary file analysis tool.
- **P Analysis**: CStatistical significance testing.
- **GCC**: Compiler for binaries.

### Methodology:
1. Instruct `angr` to execute one function at a time by specifying the binary location of the function. This prevents `angr` from delving into supporting libraries.
2. Traverse the `angr` disassembler until the desired function is located. If the function isn't found, the process halts.
3. Define a prototype for the function, basing it on the input and return types. This step uses SimTypes from `angr`.
4. Create a base `angr` state, and iterate over the parameters to mark them as symbolic. If a parameter is a pointer, its reference is made symbolic; otherwise, the argument itself is rendered symbolic.
5. Create a call state for the function and begin the `angr` simulation for symbolic execution.

### Testing:
The code was tested on a set of small test programs designed to simulate various memory types and situations including pointers, return statements, and void functions. See the test functions and generated binaries in the `test` directory in this repo. 

After the code was tested on these programs, it was tested on the GNU CoreUtils programs `ls`,`cat`, `echo`, `copy`, `chcon`, `chmod`, `chroot`, `chksum`, `date`, `dd`, `env`, and `expand`. Please note that the GNU CoreUtils were compiled locally using the guide located [here]([https://link-url-here.org](https://askubuntu.com/questions/976002/how-to-compile-the-sorcecode-of-the-offical-ls-c-source-code)).

### Results:
#### Uninitialized Memory:
`angr` struggles with the intended analysis, often leading to uninitialized memory when converting types to symbolic. This was apparent in the numerous warnings about unspecified values. The logs suggest that when a type is converted to symbolic, `angr` tends to erase the memory at the designated locations.

Following are the results from a test:
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
Similar outcomes were observed across all test files.

For GNU CoreUtils, the results mirrored those of the test programs, with the utilities compiling and executing, but without producing any initialized values.

#### Time Analysis
The modified angr code and unmodified angr were run on the same test files, the small binaries and a selection of the CoreUtils programs. 

The run times were collected from 30 runs each for all of the small programs, and one time each for the CoreUtils program.

**Small Binary Average Times:**
| Binary Name   | Modified Time (s) | Unmodified Time (s) |
|---------------|-------------------|---------------------|
| test_pointer  | 0.554             | 0.305               |
| test_binary   | 10.748            | 11.490              |
| test_binary_2 | 0.357             | 0.310               |
| test_error    | 0.365             | 0.357               |
| test_ret      | 0.333             | 0.292               |
| test_files    | 3.968             | 3.932               |

**CoreUtils Program Times:**
| Program Name | Modified Time (s) | Unmodified Time (s) | Lines |
|--------------|-------------------------|---------------------------|-------|
| ls           | 5305.930519             | 5279.957392               | 5663  |
| cat          | 415.2857319             | 438.9305286               | 804   |
| echo         | 128.3720511             | 104.5029386               | 273   |
| copy         | 6817.581057             | 6832.592021               | 3499  |
| chcon        | 376.227018              | 375.8094729               | 588   |
| chmod        | 264.7638514             | 274.246351                | 572   |
| chroot       | 488.9328208             | 493.4185769               | 433   |
| cksum        | 96.153172               | 93.75068218               | 271   |
| date         | 530.1568968             | 528.1104385               | 680   |
| dd           | 4747.304732             | 4732.14836                | 2565  |
| env          | 954.4363603             | 948.3810556               | 902   |
| expand       | 105.307867              | 122.0194856               | 237   |


In the P analysis for small binaries:
- T-statistic: -0.426
- p-value: 0.688

For the CoreUtils programs:
- T-statistic: 0.122
- p-value: 0.905

Both p-values exceed 0.05, suggesting no significant difference in execution times between the modified and unmodified `angr`. The results imply that the performance of `angr`, in terms of time, remains largely unaffected by the modifications.

As such, there is not enough evidence to reject the null hypothesis. The changes made to `angr` do not have a statistically significant effect on the overall performance across all test programs.

#### Conclusion:
The lack of a significant time difference indicates that the modifications to `angr` do not detrimentally impact its performance. However, the consistent issue of uninitialized memory across different binaries signifies a limitation in the current approach of handling symbolic execution at the function level.

### Challenges:
- **Symbolic Memory Handling**: Shifting to symbolic values often results in memory being reset, which is problematic for function-level granularity.
- **Missing Initialization**: Warnings indicate issues with accessing variables or regions that have not been properly initialized, a common hurdle in symbolic execution.

### How to Run:
1. Get a test file and compile it using GCC to generate a binary.
2. Decompile the binary with NM or a similar tool to retrieve function addresses.
3. Update the code with the binary name, path, and function address: `execute_func('tests/test_ret', 'sub_100003f80')`.
4. If necessary, modify the Prototype types (e.g., `prototype = SimTypeFunction(SimTypeInt(), SimTypeInt())`) to align with the function you're analyzing.
5. Set up a Python virtual environment and activate it.
6. Install `angr`.
7. In the virtual environment, execute `python3 loader.py`. Adjust print statements as required.

Note: Make sure you're working within the virtual environment when running the analysis to avoid dependency issues, especially if you are on an Apple machine. :)
