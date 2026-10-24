+++
date = '2026-10-24'
draft = false
title = 'Babyfuscation'
tags = ["reverse-engineering", "ghidra", "gdb", "linux", "c++"]
summary = "Reversing an obfuscated ELF binary with Ghidra & implementing a decoding function."
+++

## CTF Overview

Today I got my hands on an ELF binary from [Hackropole](https://hackropole.fr/en/) that obfuscated its function names, reimplemented library functions to avoid import names and introduced a flag encoding function that I had to revert - [Babyfuscation](https://hackropole.fr/en/challenges/reverse/fcsc2025-reverse-babyfuscation/). I found this challenge really fun as I had to implement decoding functionality and capture the flag that way.

## Setup and Workflow

I keep practising with `Ghidra` and `gdb` mostly, and today was no exception to it.

> NOTE: some functions and variables presented in the snippets have been changed from their initial meaningless names to be more readable.

1. On the `strings` command I instantly noticed some weird function names. In the `main()` function I can also see meaningless function and variable names. That's the first obfuscation method used in the code:

```c
void main(void)
{
  int local_14;
  int local_10;
  int local_c;

  for (local_14 = 0; local_14 < 80; local_14 = local_14 + 1) {
    VYeXkgjLLMrczyw7i7dJPkyAbxqgCahe[local_14] = VYeXkgjLLMrczyw7i7dJPkyAbxqgCahe[local_14] ^ 0x42;
  }
  for (local_10 = 0; local_10 < 80; local_10 = local_10 + 1) {
    a93rEUcvwf4Ec9KHKqzFx7wL[local_10] = a93rEUcvwf4Ec9KHKqzFx7wL[local_10] ^ 0x13;
  }
  for (local_c = 0; local_c < 80; local_c = local_c + 1) {
    ouPrjEhgqPVNXCqchuzw7WTWLHnkbwqj[local_c] = ouPrjEhgqPVNXCqchuzw7WTWLHnkbwqj[local_c] ^ 0x37;
  }

  VsvYbpipYYgRoCeFtoxhtAmdFuNu3WvV();
  wKtyPoT4WdyrkVzhvYUfvqo3M9iPVMd3();
  VakkEeHbtHMpNqXPMkadR4v7K();

  return;
}
```

But the binary is not actually stripped, meaning the names are there, but the meaning is lost. The solution is to rename to whatever the variable/function does, but first I had to figure out the behaviour.

2. In the main function, we can see that there're three loops that use another obfuscation technique - `XOR encoding`. I could recognize it since I had some practice with it in `MalDev Academy`. Before the function calls, the program decodes those global strings. `XOR` encryption allows us to reverse the effect by XORing with the same key.

I decided to decrypt it dynamically with `gdb` by just setting a breakpoint on the first function and reading the strings by the address:

```
(gdb) b VsvYbpipYYgRoCeFtoxhtAmdFuNu3WvV
Breakpoint 1 at 0x5555555552f0
(gdb) run

.............

(gdb) x/s &VYeXkgjLLMrczyw7i7dJPkyAbxqgCahe
0x555555558080 <VYeXkgjLLMrczyw7i7dJPkyAbxqgCahe>:      "Enter the flag: "

(gdb) x/s &a93rEUcvwf4Ec9KHKqzFx7wL
0x5555555580e0 <a93rEUcvwf4Ec9KHKqzFx7wL>:      "Correct! You've found the flag!"

(gdb) x/s &ouPrjEhgqPVNXCqchuzw7WTWLHnkbwqj
0x555555558140 <ouPrjEhgqPVNXCqchuzw7WTWLHnkbwqj>:      "Wrong flag. Try again!"
```

These turned out to be just result strings depending on the input. Moving onto the functions.

3. The first function simply prompts to input a flag, reads it and stores in a global variable:

```c
void read_input(void) {
  long lVar1;

  puts(str_A);
  fgets(g_flagInput,80,stdin);
  lVar1 = LdUonKvqsjsJu4JdfAgtgbU9(g_flagInput,&DAT_00102004);  // strcspn reimplementation
  g_flagInput[lVar1] = 0;

  return;
}
```

4. The second function starts with counting bytes of the stored input with a reimplementation of the `strlen` library function. Then, it encodes byte by byte:

```c
void encode_input(void) {
  int bytesNum;
  int i;

  bytesNum = strlen(g_flagInput);
  for (i = 0; i < bytesNum + 1; i = i + 1) {
    encoded[i] = i * 3 + 0x1fU ^ (g_flagInput[i] * 8 | g_flagInput[i] >> 5);
  }

  encoded[bytesNum + 1] = 0;
  return;
}
```

To understand what happens in the function, let's break down the encoding part. I already converted some hex to decimal to make this mutation more readable:

> 1. The right part: `input[i] * 8 | input[i] >> 5` - left bits rotation by 3:
>       - `input[i] * 8` - `x * 8` is the same as `x << 3`, it drops top 3 bits (e.g. `abcdefgh` become `defgh000`).
>       - `input[i] >> 5` is clear, drop 5 rightmost bits (e.g. `abcdefgh` -> `00000abc`).
>       - Finally, we `OR` the result, e.g. `defgh000 | 00000abc = defghabc`
> 2. The left part: `i * 3 + 0x1f` - position-depended key:
>       - For position 0 it's `0 * 3 + 0x1f = 0x1f`, for position 1 it's `1 * 3 + 0x1f = 0x22` and so on.
> NOTE: bits are represented as letters for better understanding in the examples above

Now we know what happens to the flag. Let's look at the last function to see what happens to the encoded part.

5. The third function's behaviour is pretty clear. It compares the encoded input with a stored set of bytes and prints a result of a comparison:

```c
bool compare(void) {
  int iVar1;

  iVar1 = strcmp(encoded,jMunhwoW4bRqeCdJfXvfNrRm);
  if (iVar1 != 0) {
    puts(str_C);
  }
  else {
    puts(str_B);
  }

  return iVar1 == 0;
}
```

Now that I know where the encoded flag is stored, I can export the bytes and take them through a decoding function that I implemented based on the algorithm used by the author.

6. I copied encoded bytes from Ghidra as a `C Array` and revert the encoding part, here's the decoding function:

```cpp
void decode_flag() {
  for (int i = 0; i < 80; i++) {
    uint8_t b = ENCODED_FLAG[i];
    uint8_t key = i * 3 + 0x1f;
    uint8_t decodedByte = b ^ key;
    decoded_flag[i] = (decodedByte << 5 | decodedByte >> 3); // right bits rotation by 3
  }

  for (auto b : decoded_flag) {
    if (b == '\0') {
      break;
    }

    printf("%c", b);
  }
}
```

I just had to make sure the order of reversed algorithm is correct:
    1. XOR (decode) the byte with the same key;
    2. Rotate decoded bits by 3 to the right (inverse).

And the flag was acquired! (the part of the flag is cut)

```
[elijah@elijah-arch babyfuscation-decoder]$ g++ -std=c++17 -O2 -Wall main.cpp -o decoder
[elijah@elijah-arch babyfuscation-decoder]$ ./decoder
FCSC{e30f46b147e7a25.........093b6fb8d3}
```

## What I Learned

### Rename Obfuscated functions/variables ASAP

Rename meaningless function/variable names to improve code readability and be able to focus on the behaviour. That's what I instantly did before peeking into the program's flow.

```c
void main(void)
{
  int i;
  int j;
  int k;

  for (i = 0; i < 80; i = i + 1) {
    str_A[i] = str_A[i] ^ 0x42;
  }
  for (j = 0; j < 80; j = j + 1) {
    str_B[j] = str_B[j] ^ 0x13;
  }
  for (k = 0; k < 80; k = k + 1) {
    str_C[k] = str_C[k] ^ 0x37;
  }

  funcA();
  funcB();
  funcC();

  return;
}
```

### Library Functions Reimplementation as Obfuscation

One obfuscation method I missed initially - lib functions reimplementation. I liked the idea initially because if we use imported functions, their names might give out context and simplify reversing job.

For example, in the first function I processed, there is a `strcspn` reimplementation:

`lVar1 = LdUonKvqsjsJu4JdfAgtgbU9(g_flagInput,&DAT_00102004);`

```c
long LdUonKvqsjsJu4JdfAgtgbU9(char *param_1,char *param_2) {
  char *local_18;
  char *local_10;

  for (local_10 = param_1; local_18 = param_2, *local_10 != '\0'; local_10 = local_10 + 1) {
    for (; *local_18 != '\0'; local_18 = local_18 + 1) {
      if (*local_10 == *local_18) goto LAB_001011d1;
    }
  }
LAB_001011d1:
  return local_10 - param_1;
}
```

It's pretty much a loop that counts bytes before a "reject" byte. In my case `&DAT_00102004` is the new string (`\n`) byte. As `fgets` keeps it, the program strips it and adds a null treminator later with `g_flagInput[lVar1] = 0;` statement. Here's the global that is passed in as `*param_2`:

```
lea    0xce0(%rip),%rax        # 0x555555556004

(gdb) x/s 0x555555556004
0x555555556004: "\n"
```

## Conclusion

The more reversing challenges I solve, the harder ones I try to select next time. Today I combined all of the skills I learned to capture the flag: assembly, Ghidra, gdb, C++ and even a bit of knowledge from `MalDev Academy` from its `Code Obfuscation` module. The combination of engineering and reversing skills is what makes me keen on such challenges!

Next time I might try to work on my first real game-cheat/malware reversing as well as anti-cheat/OS software as mentioned in the previous blog post. Cya! :)
