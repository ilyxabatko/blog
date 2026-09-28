+++
date = '2026-09-28'
draft = false
title = 'Working Through CS:APP Bomb Lab'
tags = ["reverse-engineering", "gdb"]
summary = "What a binary bomb taught me about reading my first optimized assembly."
+++

## Lab Overview

Bomb Lab is one of the [practical tasks](https://csapp.cs.cmu.edu/3e/labs.html) for the "Computer Systems: A Programmer's Perspective" book by Bryant and O'Hallaron. You're provided with a binary that consists of six phases, where each expects a certain string as an input to "defuse" it. The prerequisites (in my humble opinion) are *x86 assembly*, *Computers and CPU architecture* basics, a bit of some Unix terminal experience and probably some C language understanding.

I haven't read the book personally, but this self-taught lab appeared to be a decent first practice on my Reverse Engineering journey. The **only tool** I used was **gdb**, a default Unix debugger that I got on my WSL environment.

## Setup and Workflow

As stated above, I used the one and only **gdb** debugger on my WSL environment. The bomb binary is compiled with optimizations on, which is why several of the patterns below don't look like C code that produced them (e.g. loops with the first iteration separated, division done with shifts).

I was also given a source file that includes phase function names only. The workflow was simple and straightforward:

1. Run `gdb ./bomb`
2. Read the existing function names with the `info functions` command
3. Set a breakpoint for the current phase or certain instructions (`break phase_x`, `break *0xffffff`)
4. Run the debugger with the solutions input as a text file - `run ./solutions.txt`
5. Hit the first "explosion"
6. Disassemble a given phase function - `disas phase_x`
7. Find the deciding comparison and trace backwards to where the values come from
8. Trace registers (`info registers` or `i r`), stack (`e.g. `backtrace` or `x/12xw $rsp`), certain bytes (e.g. `x/1bx $rbx`) and figure out a pattern or idea behind the phase.
9. Put some input in a solutions text file, goto step 4.

It took me 2 days and quite a few sets of iterations to get used to AT&T assembly syntax to "defuse" the bomb (including the secret phase). 

## Patterns Learned
*I'll be omitting prologues and epilogues of functions and highlighting only the parts that matters.*

### "strings_not_equal" pattern

The first function in Phase One I stumbled across was the "strings_not_equal" one:

```asm
; prologue...

; get the lengths of two strings (my input & binary's one)
call   0x40131b <string_length> ; x2

mov    $0x1,%edx ; sets the "pessimistic" default (if stirngs lengths are not equal)

; the length gate (jumps to the end of function if lengths differ)
cmp    %eax,%r12d
jne    end_of_function ; lengths differ

; the first characters are compared
movzbl (%rbx),%eax
test   %al,%al ; empty strings check
je     end_of_function
cmp    0x0(%rbp),%al
je     loop ; jumps to the loop if first chars are equal
jmp    end_of_function ; otherwise, strings are not equal

; (+50)
cmp    0x0(%rbp),%al ; same comparison as the one at +43
jne    end_of_function

; loop (+58 offset) - advance both pointers, load the next byte
add    $0x1,%rbx
add    $0x1,%rbp
movzbl (%rbx),%eax
test   %al,%al
jne    +50  ; not a null terminator, hence compare
mov    $0x0,%edx ; terminator reached, every byte matched, return 0

; (+99 offset) sets the return value
mov    %edx,%eax ; all the function's paths end up here

; epilogue...
```

That was the `strcmp()` pattern (a function to compare two strings), which is not that hard to notice if you're familiar with the C language.

### Jump Table

In Phase Three I got familiar with the "jump table" concept, which enables the navigation in a **Switch** statement. I also learned, that jump table works perfectly here as the switch cases grouped closely, and it runs in O(1) constant time.

```asm
cmpl   $0x7,0x8(%rsp)
ja     0x400fad <phase_3+106> ; jumps to 'default case' if my input is out of the range
mov    0x8(%rsp),%eax
jmp    *0x402470(,%rax,8) ; the 'indirect' jump to the case by indexing the table
```

The `ja` instruction is the "jump if above" unsigned one, hence it also checks unsigned bounds.

We can inspect the jump table entries with, for example, the `x/8a [address]` gdb command, which prints us 8 memory addresses and the functions they point to.
![Phase 3 Jump table entries](/images/bomb-lab/jt.png)

### Signed division by 2

In Phase Four (which we'll discuss in more details later), I got familiar with this clever compiler's approach on the *signed divison by 2* approach:

```asm
mov    %edx,%eax  ; get the upper bound
sub    %esi,%eax  ; eax = upper - lower (can be positive or negative)
mov    %eax,%ecx
shr    $0x1f,%ecx ; get the 'sign bit' by shifting right by 31 bits
add    %ecx,%eax ; add the sign bit to the bounds difference calculated above
sar    $1,%eax ; shift right by 1, which is a 'by 2 division' simply
lea    (%rax,%rsi,1),%ecx ; result of the division + lower bound
```

Here, `sar` instruction rounds toward negative infinity, while C requires rounding toward zero, so adding `1` to negative values before the shift corrects the difference. E.g., `-7 >> 1 = -4`, but `-7 / 2 = -3`. Though, it's a dead end in this particular case as the upper and lower boudns are never negative, the compiler can't prove that and emits such a form.

### Stack canary

In Phase 5 I learned a technique that protects a program against *buffer overflow* attacks. A random value is placed on the stack above the locals. That way, if someone tries to overwrite a local variable, the canary will be overwritten as well. The secret random value is generated on the program start and stored in **Thread Local Storage**, a secure memory location.

```asm
; prologue
mov    %fs:0x28,%rax ; get a generated value from TLS
mov    %rax,0x18(%rsp) ; put it on the stack
xor    %eax,%eax ; clear the register

; epilogue
mov    0x18(%rsp),%rax ; load the value back
xor    %fs:0x28,%rax ; compare the value with the TLS one
je     0x4010ee <phase_5+140> ; if 0, then the values are equal
call   0x400b30 <__stack_chk_fail@plt> ; if the values doesn't match - terminate
```

## Hard Phase

Phase Four turned out to be the one I got stuck hardly with. The main challenge was in identifying the intent of the function, even though I could solve the phase by satisfying all of the comparisons.

The `phase_4` function's setup parses two input numbers, gates it with `cmpl $0xe, 0x8(%rsp)` and `jbe` to make sure that the first input is below or equal 14. Then a fixed range is set, and the `func4`is called.

The 2nd number was the separate `cmpl $0x0, 0xc(%rsp)` gate, it simply must be 0.

```asm
mov    $0xe,%edx ; edx = 14
mov    $0x0,%esi ; esi = 0
mov    0x8(%rsp),%edi ; rdi = first input number
call   0x400fce <func4>
test   %eax,%eax ; the 'func4' return value must be 0 to succeed
jne    explode

; 2nd number gate
cmpl   $0x0,0xc(%rsp)
je     defused
```

Now let's examine `func4`, which includes the *Binary Search* algorithm that I couldn't identify upon my first examination and solution.

The first part of the function is about calculating the middle of the range, the *signed division by 2* pattern that I discussed above. Then the middle point and the target value are compared.

```asm
; signed division by 2

; compare calculated middle point against my input number
cmp    %edi,%ecx
```

We have three branches, depending on the comparison result:

### 1. Midpoint > Target

```asm
lea    -0x1(%rcx),%edx ; decrement the upper bound
call   func4 ; recursion
add    %eax,%eax ; double eax (return value)
ret
```

### 2. Midpoint == Target

```asm
mov    $0x0,%eax
ret
```

### 3. Midpoint < Target

```asm
lea    0x1(%rcx),%esi ; increment the lower bound
call   func4 ; recursion
lea    0x1(%rax,%rax,1),%eax ; 2 * return value + 1
```

### Insights 

Let's recall that the output of `func4` must be 0 in order to defuse the function. The binary search range is `from 0 to 14`.

We can notice, that in the third branch (when the middle point less than a target), on the recursion return the output value is *at least incremented once* (`lea 0x1(%rax,%rax,1),%eax`), poisoning the result permanently.

With that rule, the `lower bound is always 0`, the `upper bound moves as hi = mid - 1` (14 -> 6 -> 2 -> 0), and the `middle point at each step is 7, 3, 1, 0`. These four midpoints are the only numbers the search reaches without ever taking the upper-half move (where `midpoint < target` and the return value (`rax`) is increased). Every other input forces at least one `lea 0x1(%rax,%rax,1),%eax` in the return chain that poisons the output.

Hence the answer can be any middle point of the lower-half of the given range (`0 ... 14`).

## Where I Got Stuck

### Symmetric test data hid the transformation

In Phase Six I input six values, `6 5 4 3 2 1`, and the loop produced `1 2 3 4 5 6`, hence I read the pattern as an array reversal, when it actually was `7 - value` applied.

```asm
mov   $0x7,%ecx
mov   %ecx,%edx
sub   (%rax),%edx
mov   %edx,(%rax)
```

In such unknown functions, using asymmetric input is a good practice so that an output can't be mistaken for a permutation.

### Solving a phase without understanding one branch

In Phase Six, a linked list is created from a set of nodes, and my input affects the order. I read the assembly, managed to find the nodes, figured out the descending order requirement for the nodes' inner values, but I couldn't notice the part that selects which node each input maps to.

I couldn't work backwards to an input as I had read the selection loop as *"value picks node"* and forgotten that `7 - v` sat in front of it (the data transformation problem I mentioned above).

Here's the transformation part I didn't pay enough attention to: 

```asm
mov  %r14,%rax ; rax = &values[0]
mov  $0x7,%ecx

; loop
mov  %ecx,%edx
sub  (%rax),%edx ; edx = 7 - value
mov  %edx,(%rax) ; write back
add  $0x4,%rax
cmp  %rsi,%rax  ; rsi = &values[6]
jne  loop
```

## Summary

This lab was quite a challenge for me, especially considering the lack of experience and proper notes, but I enjoyed solving it a lot with *gdb* only.

The most important lesson I learned: **always make notes**, draw workflow schemas, maybe some registers' purposes, especially when encountering a confusing pattern. That way I can always go back and recall any mutation that happens during a program's flow.

Now I move on to so called `crackmes` where I'll learn much more about Reverse Engineering techniques and tools, especially Ghidra.
