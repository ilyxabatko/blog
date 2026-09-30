+++
date = '2026-09-30'
draft = false
title = 'Aaarg Hackropole CTF'
tags = ["reverse-engineering", "ghidra", "gdb"]
summary = "Solving a Hackropole Reversing CTF with Ghidra"
+++

## CTF overview

`Aaarg` is the first and, most likely, easiest Reverse challenge from the [Hackropole](https://hackropole.fr/en/) platform that archives *France Cybersecurity Challenge* CTF competitions.

## Setup and Workflow

There's no required way to approach this challenge, hece I decided to use **Ghidra** for the first time to get familiar with this static analysis tool. The UI is quite clean and straightforward if you used other RE tools before such as gdb, x64dbg, etc. The steps I took to begin were:

1. Installed Ghidra on my Arch Linux machine ofc :D
2. Created the project and imported downloaded `aaarg` binary.
3. Ran binary analysis in Ghidra.
4. Found the `processEntry` function (binary entry).
5. Found the (main) function address on the assembly window before the `__libc_start_main` call:
    ```asm
    0040106d MOV    RDI, FUN_00401190    ; the first argument goes to RDI, so that's the "main" func
    ```
6. Read the decompiled code, rewrite signatures and variable names.
7. Understand the problem, satisfy checks and get the solution key.

This CTF was even simpler than Bomb Lab, but I enjoyed working with Ghidra that simplifies a lot of steps compared to gdb and saves much time.

## What I Learned

### Recon first

Starting the reversing process with "recon" might give a lot of useful information on the binary. For example, by looking at the `file ./aaarg` command output, I found that it's not a `PIE executable` meaning the addresses are fixed, or that the executable is `stripped` meaning the function names are not preserved.

Then with `ltrace ./aaarg test` I found the first call to `strtoul` and it gave me the idea that I must provide some arguments.

The `checksec file aaarg` also gives a decent overview on the file, even though I'm not familiar with most of these flags:

```
Partial RELRO  No Canary Found  Unknown  NX enabled  PIE Disabled  No RPATH  No RUNPATH  No Symbols  No SafeStack Found  No Probes    Enabled  No Selfrando  aarg
```

For example, we can see that there's no `Stack Canary` which protects against buffer overflow attacks.

### Rewrite signatures, rename variables in Ghidra

It's a small thing to understand early when working with Ghidra as it makes the decompiled code way more readable and saves time drastically.

For example, look at the `strtoul` function call:

```c
// Ghidra's default output
uVar1 = strtoul(*(char **)(param_2 + 8), &end_str, 10);

// After setting the signature to int main(int argc, char **argv)
n = strtoul(argv[1], &end_str, 10);
```

The initial version with raw pointer math is taken from assembly `MOV RDI, qword ptr [RSI + 0x8]` as Ghidra didn't know `param_2` was an array of pointers.

## Solution

After function signature and variables are rewritten, we have a pretty clean decompilation:

```c
int main(int argc,char **argv)
{
  int status;
  ulong n;
  char *end_str;

  status = 1;
  if (1 < argc) {
    n = strtoul(argv[1],&end_str,10);
    status = 1;

    if ((*end_str == '\0') && (status = 2, n == (long)-argc)) {
      n = 0;

      do {
        putc((int)(char)(&DAT_00402010)[n],stdout);
        n = n + 4;
      } while (n < 0x116);

      putc(10,stdout);
      status = 0;
    }
  }

  return status;
}
```

> One note about the `strtoul` function output: if the numeric literal has `minus` prefix, the output is wrapped around.
> The `n` variable is optimized and it represents both the `strtoul` output first, then array counter, because the compiler reused one register for both values.

The overall idea is simple:
1. convert the first argument to a number (`unsigned long, 64 bits`), rejects the input unless the whole string is numeric;
2. compare that number to the negated count of arguments;
3. if these are equal (discussed down below), process body of if condition;
4. in the loop, get every 4th byte (real message) from the address while `n < 0x116` and print to output.

### Where I Had To Think

The main catch for me was the `n == (long)-argc` condition. Initially I thought "it's always false as `n` is always positive, and negated arguments counter (`-argc`) is always negative". But the assembly made it obvious:

```asm
NEG    EBX        ; -argc, still 32-bit
MOVSXD RDX, EBX   ; widen to 64-bit with sign extension
CMP    ...        ; compare
```

> `-2` in 64-bit is `0xFFFFFFFFFFFFFFFE`. Signed reads as `-2`and unsigned is `2^64 - 2 = 18446744073709551614`, bits are still the same.

It's clear that `CMP`compares two 64-bits values and signedness doesn't matter.
Then I had to recall that when C compares an `unsigned long n` with a `signed long argc`, the latter is converted to `unsigned long`, so wraparound happens.

Now the condition is clear and we can proceed to the solution, any of these work:

```
./aaarg 18446744073709551614  # wraparound of -2
./aaarg -2
./aaarg -3 X
./aaarg -4 X Y   # and so on...

# Result:
FCSC{f9a38adace9dda3a9ae53e7aec180c5a73dbb7c364fe137fc6721d7997c54e8d}
```

Only the first argument's value matters, and the rest just for the correct `argc` count.

## Bonus Finding

There's one more interesting thing I found following that data pointer from the main function:

```asm
DAT_00402010    XREF[2]:     FUN_00401140:00401150(R),
                             main:004011e0(R)
```

There's one function address that is not the one I worked on and decided to check it. It turned out to likely be a helper left over as a standalone copy. It's never called, though there're a couple references to it in `.eh_frame` and `.eh_frame_hrd`. The helper was probably inlined into the `main`function and wasn't `static`, hence the compiler emitted a standalone copy.


```c
void FUN_00401140(void)
{
  ulong uVar1;

  uVar1 = 0;

  do {
    putc((int)(char)(&DAT_00402010)[uVar1],stdout);
    uVar1 = uVar1 + 4;
  } while (uVar1 < 0x116);

  putc(10,stdout);
  return;
}
```

That's pretty much the `main` function from above with no conditions, and I can abuse it with, for example, `gdb` the following way:

```
gdb ./aaarg
b *0x401190     # set breakpoint to main function
run
set $rip = 0x401140   # modify the instruction pointer to point to the "hidden" function
c
```

And it will print the solution with no effort. Lovely!
